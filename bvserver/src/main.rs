use std::{collections::HashMap, fs::File, io::Write, net::{IpAddr, Ipv4Addr, SocketAddr}, str::FromStr, sync::Arc};

use bytes::{Bytes, BytesMut};
use clap::Parser;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::{mpsc::{self, error::TrySendError}, RwLock}, time};

mod config;
mod delay;
mod p2p;
mod netaddr;
mod forward;
mod ip;

static mut NONCE: String = String::new();

fn prefix2mask(prefix: u8) -> Ipv4Addr {
    // 确保 prefix 在 0 到 32 的范围内
    assert!(prefix <= 32);

    // 计算掩码，将高位的 prefix 位设置为 1，其余位设置为 0
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    // 将 mask 转换为 IPv4 地址
    Ipv4Addr::from(mask)
}

/// Config
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path of the config file
    #[arg(short, long, default_value_t = String::from_str("bvserver-config.yml").unwrap())]
    config: String,
}

const MTU: usize = 1400;

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();
    let cfg = config::Config::from_file(&args.config);

    unsafe {
        NONCE.push_str(&cfg.cipher_config.nonce);
    }

    if cfg!(target_os = "windows") {
        // 包含wintun
        let wintun_dll = include_bytes!("../../wintun.dll");
        if let Err(_) = std::fs::metadata("wintun.dll") {
            // 文件不存在
            let mut file = File::create("wintun.dll").expect("Failed to create file");
            file.write_all(wintun_dll).expect("Failed to write to file");
        }
    }

    // 处理tun设备
    let ipp: Vec<&str> =  cfg.tun.ip.split('/').collect();
    let prefix = u8::from_str(ipp.get(1).unwrap()).unwrap();
    let tun_ip = IpAddr::from_str(ipp.get(0).unwrap()).expect("error tun ip");
    let mut config = tun::Configuration::default();
    config
        .tun_name(&cfg.tun.name)
        .address(tun_ip)
        .netmask(prefix2mask(prefix))
        .mtu(MTU as u16)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    let dev = tun::create_as_async(&config).unwrap();
    
    let (mut rdev, mut wdev) = tokio::io::split(dev);

    // 主通道
    let (main_sender, mut main_receiver) = mpsc::channel::<Bytes>(100);
    // 客户端通道
    let customer_sender_map = Arc::new(RwLock::new(HashMap::<IpAddr, (SocketAddr, time::Instant, mpsc::Sender<Bytes>)>::new()));
    // let source_packet_record = Arc::new(Mutex::new(HashMap::<IpAddr, time::Instant>::new()));
    // 真实地址跟虚拟地址对照表
    // let r2vmap = Arc::new(RwLock::new(HashMap::<SocketAddr, IpAddr>::new()));


    let _customer_sender_map = customer_sender_map.clone();
    tokio::task::spawn(async move {
        // 虚拟网卡读
        loop {
            let mut buf = BytesMut::with_capacity(4096);
            rdev.read_buf(&mut buf).await.unwrap();
            let (_, dst) = match ip::version(&buf) {
                ip::Version::V4(src, dst) => {
                    // 拒绝组播、多播udp，仅支持单播
                    if (dst.octets()[0] >= 224 && dst.octets()[0] <= 239) || dst.octets()[3] == 255
                    {
                        continue;
                    }
                    (IpAddr::V4(src), IpAddr::V4(dst))
                }
                _ => {
                    continue;
                }
            };
            // 转发到对应的目的地
            let mut m = _customer_sender_map.write().await;
            if let Some((_, _, s)) = m.get_mut(&dst) {
                match s.try_send(buf.freeze()) {
                    Ok(()) => {

                    }
                    Err(TrySendError::Closed(_)) => {
                        // 通道关闭
                        log::info!("{} channel closed.", line!());
                        _ = m.remove(&dst);
                    }
                    Err(TrySendError::Full(_)) => {
                        // 队列满了，直接丢弃
                        log::info!("{} channel full.", line!());
                    }
                }
            }
        }
    });
    let _customer_sender_map = customer_sender_map.clone();
    tokio::spawn(async move {
        // 虚拟网卡写
        loop {
            let buf = main_receiver.recv().await.unwrap();
            // 目的地是否其他客户端
            let (_, dst) = match ip::version(&buf) {
                ip::Version::V4(src, dst) => {
                    (IpAddr::V4(src), IpAddr::V4(dst))
                }
                _ => {
                    continue;
                }
            };
            let mut m = _customer_sender_map.write().await;
            if let Some((_, t, s)) = m.get_mut(&dst) {
                *t = time::Instant::now();
                // 转发给其他客户端
                match s.try_send(buf) {
                    Ok(()) => {}
                    Err(TrySendError::Closed(_)) => {
                        // 通道关闭
                        log::info!("{} channel closed.", line!());
                        _ = m.remove(&dst);
                    }
                    Err(TrySendError::Full(_)) => {
                        // 队列满了，直接丢弃
                        log::info!("{} channel full.", line!());
                    }
                }
            } else {
                wdev.write_all(&buf).await.unwrap();
                wdev.flush().await.unwrap();
            }

        }
    });

    let _customer_sender_map = customer_sender_map.clone();
    tokio::spawn(async move {
        // 检查源ip是否10分钟内没来数据了，是的话剔除会话列表
        loop {
            time::sleep(time::Duration::from_secs(60 * 10)).await;
            let _now = time::Instant::now();
            _customer_sender_map.write().await.retain(|_, (_, t, _) | _now.duration_since(*t).as_secs() < 600);
            log::info!("check retain client {}", _customer_sender_map.read().await.len());
        }
    });


    // 中继模式
    let rcfg = cfg.relay_config.clone();
    let cfg1 = cfg.clone();
    let _main_sender = main_sender.clone();
    let _customer_sender_map = customer_sender_map.clone();
    // let _r2vmap = r2vmap.clone();
    tokio::spawn(async move {
        let mut dly = delay::Delay::new();
        match rcfg {
            Some(rcfg) => {
                log::info!("start relay mode.");
                loop {
                    let peer_info = p2p::get_peer_addr(rcfg.clone()).await;
                    if peer_info == None {
                        log::info!("RELAY DOWN.");
                        dly.delay().await;
                        continue;
                    }
                    let cfgc = cfg1.clone();
                    let __main_sender = _main_sender.clone();
                    let __customer_sender_map = _customer_sender_map.clone();
                    tokio::spawn(async move {
                        match peer_info {
                            Some((_bind, _)) => {
                                forward::forever(_bind, cfgc, true, __main_sender, __customer_sender_map).await;
                            }
                            None => {
                                log::info!("RELAY DOWN.");
                            }
                        }
                    });
                }
            }
            None => {
                log::info!("no relay config");
            }
        }
    });

    // 直连模式
    let dcfg = cfg.direct_config.clone();
    tokio::spawn(async move {
        match dcfg {
            Some(dcfg) => {
                let bind = SocketAddr::from_str(&dcfg.bind).unwrap();
                log::info!("start direct mode.");
                let _main_sender = main_sender.clone();
                let _customer_sender_map = customer_sender_map.clone();
                forward::forever(bind, cfg, false, _main_sender, _customer_sender_map).await;
            }
            None => {
                log::info!("no direct config");
            }
        }
    });

    log::info!("ctrl + c to exit.");
    tokio::signal::ctrl_c().await.unwrap();
}
