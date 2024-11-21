use std::{fs::File, io::Write, net::{IpAddr, Ipv4Addr, SocketAddr}, str::FromStr};

use bytes::{Bytes, BytesMut};
use clap::Parser;

use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::mpsc};
#[cfg(target_os = "windows")]
use tun::AbstractDevice;

mod p2p;
mod config;
mod netaddr;
mod forward;
mod ip;
mod buffer;
mod delay;
/// Config
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path of the config file
    #[arg(short, long, default_value_t = String::from_str("bvclient-config.yml").unwrap())]
    config: String,
}

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

fn binmatch(n: u8) -> Option<u8> {
    match n {
        0b0000_0000 => Some(0),
        0b1000_0000 => Some(1),
        0b1100_0000 => Some(2),
        0b1110_0000 => Some(3),
        0b1111_0000 => Some(4),
        0b1111_1000 => Some(5),
        0b1111_1100 => Some(6),
        0b1111_1110 => Some(7),
        0b1111_1111 => Some(8),
        _ => None,
    }
}

// 255.255.252.0 -> 22
fn mask2prefix(mask: &str) -> u8 {
    let sp: Vec<&str> = mask.split(".").collect();
    let a: u8 = sp[0].parse().unwrap();
    let b: u8 = sp[1].parse().unwrap();
    let c: u8 = sp[2].parse().unwrap();
    let d: u8 = sp[3].parse().unwrap();
    let mut res = 0;
    if let Some(k) = binmatch(a) {
        res += k;
    }
    if let Some(k) = binmatch(b) {
        res += k;
    }
    if let Some(k) = binmatch(c) {
        res += k;
    }
    if let Some(k) = binmatch(d) {
        res += k;
    }
    res
}

fn route_with_mask(route: String) -> String {
    let mut route = route;
    if !route.contains("/") {
        route = route + "/32";
    }
    let rm: Vec<&str> = route.split("/").collect();
    let mask = rm[1];
    if mask.contains(".") {
        // eg. 255.255.0.0
        let prefix = mask2prefix(mask);
        route = format!("{}/{}", rm[0], prefix);
    }
    return route;
}

fn split_addr(cidr: &str) -> (Ipv4Addr, u8) {
    let ipp: Vec<&str> =  cidr.split('/').collect();
    let prefix = u8::from_str(ipp.get(1).unwrap()).unwrap();
    let ip: Ipv4Addr = Ipv4Addr::from_str(ipp.get(0).unwrap()).expect("error tun ip");
    (ip, prefix)
}

const MTU: usize = 1400;

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();
    let cfg = config::Config::from_file(&args.config);

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
    log::info!("ip address is {}", cfg.tun.ip);
    let (tun_ip, prefix) = split_addr(&cfg.tun.ip);
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

    // 设置路由
    #[cfg(target_os = "windows")]
    {
        let index = dev.tun_index().unwrap();
        log::info!("tun index is {}", index);
        if let Some(routes) = cfg.out_routes.clone() {
            for mut route in routes {
                route = route_with_mask(route);
                let set_route = format!("netsh interface ip add route {} {}", route, index);
                log::info!("{}", set_route);
                std::process::Command::new("cmd")
                    .arg("/C")
                    .arg(set_route)
                    .output()
                    .unwrap();
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(routes) = cfg.out_routes.clone() {
            for mut route in routes {
                route = route_with_mask(route);
                let set_route = format!("ip route add {} dev {}", route, &cfg.tun.name);
                log::info!("{}", set_route);
                std::process::Command::new("sh")
                    .arg("-c")
                    .arg(set_route)
                    .output()
                    .unwrap();
            }
        }
    }
    let (mut rdev, mut wdev) = tokio::io::split(dev);

    let (mut dev_sender, mut dev_receiver) = mpsc::channel::<Bytes>(100);
    let (soc_sender, mut soc_receiver) = mpsc::channel::<Bytes>(100);


    tokio::task::spawn(async move {
        // 虚拟网卡读
        loop {
            let mut buf = BytesMut::with_capacity(4096);
            if let Err(_) = rdev.read_buf(&mut buf).await {
                continue;
            }
            match ip::version(&buf) {
                ip::Version::V4(_, dst) => {
                    // 拒绝组播、多播udp，仅支持单播
                    if (dst.octets()[0] >= 224 && dst.octets()[0] <= 239) || dst.octets()[3] == 255
                    {
                        continue;
                    }
                }
                _ => {
                    continue;
                }
            };
            _ = soc_sender.try_send(buf.freeze());
        }
    });

    tokio::spawn(async move {
        loop {
            let buf = dev_receiver.recv().await.unwrap();
            wdev.write(&buf).await.unwrap();
        }
    });

    let mut d = delay::Delay::new();
    loop {
        let _cfg = cfg.clone();
        let rcfg = cfg.relay_config.clone();
        let _tun_ip = tun_ip.clone();
        match rcfg {
            Some(rcfg) => {
                let peer_info = p2p::get_peer_addr(rcfg).await;
                match peer_info {
                    Some((_bind, _peer)) => {
                        log::info!("start relay mode.");
                        (dev_sender, soc_receiver) = forward::forever(_bind, _peer, _tun_ip, _cfg.clone(), dev_sender, soc_receiver).await;
                    }
                    None => {
                        log::info!("STOP.")
                    }
                }
            }
            None => {
                // 直连模式
                let dcfg = cfg.direct_config.clone();
                match dcfg {
                    Some(dcfg) => {
                        log::info!("start direct mode.");
                        let _peer = netaddr::get_one_addr(&dcfg.server).await.unwrap();
                        (dev_sender, soc_receiver) = forward::forever(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), _peer, _tun_ip, _cfg.clone(), dev_sender, soc_receiver).await;
                    }
                    None => {
                        log::info!("STOP.");
                    }
                }
            }
        }
        d.delay().await;
    }
    
}
