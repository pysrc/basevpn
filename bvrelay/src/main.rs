use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    net::{SocketAddr, UdpSocket},
    str::FromStr,
    time::Instant,
};

use clap::Parser;
use serde::{Deserialize, Serialize};
use sha1::Digest;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    bind: String,
    salt: String,
    #[serde(rename = "allow-relay")]
    allow_relay: bool,
    #[serde(rename = "allow-group-id")]
    allow_group_id: Vec<String>,
}

impl Config {
    fn from_file(filename: &str) -> Self {
        let f = File::open(filename);
        match f {
            Ok(mut file) => {
                let mut c = String::new();
                file.read_to_string(&mut c).unwrap();
                let cfg: Config = serde_yaml::from_str(&c).unwrap();
                cfg
            }
            Err(e) => {
                panic!("error {}", e)
            }
        }
    }
}

struct Peer {
    addr: SocketAddr,
    instant: Instant,
}

/// Config
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path of the config file
    #[arg(short, long, default_value_t = String::from_str("bvrelay-config.yml").unwrap())]
    config: String,
}

fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();
    let cfg = Config::from_file(&args.config);
    let mut hasher = sha1::Sha1::new();
    let mut group_id_set = HashSet::<[u8; 20]>::with_capacity(cfg.allow_group_id.len());
    for ele in cfg.allow_group_id {
        hasher.update(ele.as_bytes());
        let gp = hasher.finalize_reset();
        let mut gps = [0u8; 20];
        gps.copy_from_slice(gp.as_slice());
        log::info!("GROUP {:?}", gps);
        group_id_set.insert(gps);
    }
    let socket = UdpSocket::bind(&cfg.bind).unwrap();
    log::info!("bind on: {}", cfg.bind);
    let mut buffer = vec![0u8; 4096];

    let mut hart_peer_map = HashMap::<[u8; 20], Peer>::new(); // 心跳表
    let mut relay_map = HashMap::<SocketAddr, Peer>::new(); // 转发表
    let mut last_clear = Instant::now(); // 上次清理时间
    const MAX_IDLE: u64 = 300;
    loop {
        if last_clear.elapsed().as_secs() > MAX_IDLE {
            // MAX_IDLE秒清理一次
            // 清理心跳表
            let mut clear_set1 = HashSet::new();
            hart_peer_map.iter().for_each(|(k, v)| {
                if v.instant.elapsed().as_secs() > MAX_IDLE {
                    clear_set1.insert(k.clone());
                }
            });
            for key in clear_set1 {
                let old = hart_peer_map.remove(&key);
                if let Some(old) = old {
                    log::info!("{} clear hart map {}", line!(), old.addr);
                }
            }
            // 清理中继表
            if cfg.allow_relay {
                let mut clear_set2 = HashSet::new();
                relay_map.iter().for_each(|(k, v)| {
                    if v.instant.elapsed().as_secs() > MAX_IDLE {
                        clear_set2.insert(k.clone());
                    }
                });
                for key in clear_set2 {
                    let old = relay_map.remove(&key);
                    if let Some(old) = old {
                        log::info!("{} clear relay map {}", line!(), old.addr);
                    }
                }
            }
            last_clear = Instant::now();
        }
        match socket.recv_from(&mut buffer) {
            Ok((n, src)) => {
                if cfg.allow_relay {
                    // 判断是不是中继
                    let remove = match relay_map.get_mut(&src) {
                        Some(peer) => {
                            peer.instant = Instant::now();
                            if let Err(e) = socket.send_to(&buffer[..n], peer.addr) {
                                log::info!("{} {}", line!(), e);
                                Some(peer.addr.clone())
                            } else {
                                None
                            }
                        }
                        None => None,
                    };
                    if let Some(addr) = remove {
                        relay_map.remove(&src).unwrap();
                        relay_map.remove(&addr);
                        continue;
                    }
                }
                if n < 21 {
                    continue;
                }
                // 校验数据包是否合法
                hasher.update(&cfg.salt.as_bytes());
                hasher.update(&buffer[20..n]);
                let ghash = hasher.finalize_reset();
                let ihash = ghash.as_slice();
                if ihash != &buffer[..20] {
                    // 校验不通过
                    continue;
                }
                match buffer[20] {
                    1 => {
                        // inside心跳
                        // 检查group是否被允许
                        if group_id_set.contains(&buffer[21..41]) {
                            match hart_peer_map.get_mut(&buffer[21..41]) {
                                Some(peer) => {
                                    peer.instant = Instant::now();
                                    peer.addr = src;
                                }
                                None => {
                                    let mut gp = [0u8; 20];
                                    gp.copy_from_slice(&buffer[21..41]);
                                    hart_peer_map.insert(
                                        gp,
                                        Peer {
                                            addr: src,
                                            instant: Instant::now(),
                                        },
                                    );
                                }
                            }
                            _ = socket.send_to("OK".as_bytes(), src);
                        }
                    }
                    2 => {
                        // 地址响应
                        match hart_peer_map.remove(&buffer[21..41]) {
                            Some(peer) => {
                                let ssrc = peer.addr.to_string();
                                _ = socket.send_to(ssrc.as_bytes(), src);
                                _ = socket.send_to(src.to_string().as_bytes(), peer.addr);
                            }
                            None => {
                                log::info!("server not login.");
                                _ = socket.send_to("NOPEER".as_bytes(), src);
                            }
                        }
                    }
                    3 => {
                        // 中继要求
                        if cfg.allow_relay {
                            // 校验group
                            if group_id_set.contains(&buffer[21..41]) {
                                // 取中继目标地址
                                let dst = String::from_utf8_lossy(&buffer[41..n]).to_string();
                                match SocketAddr::from_str(&dst) {
                                    Ok(dst) => {
                                        relay_map.insert(
                                            src,
                                            Peer {
                                                addr: dst,
                                                instant: Instant::now(),
                                            },
                                        );
                                        _ = socket.send_to("RELAY".as_bytes(), src);
                                    }
                                    Err(e) => {
                                        log::info!("{} {}", line!(), e);
                                    }
                                }
                            }
                        } else {
                            _ = socket.send_to("NORELAY".as_bytes(), src);
                        }
                    }
                    _ => {
                        continue;
                    }
                }
            }
            Err(e) => {
                log::info!("{} {}", line!(), e);
            }
        }
    }
}