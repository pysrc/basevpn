use std::{
    net::{Ipv4Addr, SocketAddr}, str::FromStr, sync::{atomic::{AtomicBool, Ordering}, Arc}
};

use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // 使用 ChaCha20-Poly1305 实现
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::UdpSocket, time::{timeout, Instant}};

#[cfg(target_os = "windows")]
use tun::AbstractDevice;

use crate::{ config::{self, MetaInfo}, ip, MTU};

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

static RUNNING: AtomicBool = AtomicBool::new(true);

static mut NONCE: String = String::new();

pub async fn forever(bind: SocketAddr, peer: SocketAddr, cfg: config::Config) {
    
    // 1. 初始化密钥和 nonce（随机数）
    let _k = cfg.cipher_config.key.clone();
    unsafe {
        NONCE.push_str(&cfg.cipher_config.nonce);
    }
    
    let key = Key::from_slice(_k.as_bytes()); // 密钥长度必须是 32 字节
    let nonce = unsafe { Nonce::from_slice(NONCE.as_bytes()) }; // 12 字节的 nonce

    // 2. 创建加密器实例
    let mut cipher = ChaCha20Poly1305::new(key);

    let soc = UdpSocket::bind(bind).await.unwrap();
    soc.connect(peer).await.unwrap();
    log::info!("local and remote: {} -> {}", soc.local_addr().unwrap(), peer);
    // 处理tun设备
    log::info!("ip address is {}", cfg.tun.ip);
    let (tun_ip, prefix) = split_addr(&cfg.tun.ip);
    // 心跳包
    let mut hart_buf = vec![0u8;5];
    hart_buf[4] = bvcommon::TYPE_HART;
    hart_buf[0..4].copy_from_slice(&tun_ip.octets());

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
        if let Some(routes) = cfg.out_routes {
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
        if let Some(routes) = cfg.out_routes {
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

    let soc = Arc::new(soc);

    let _soc = soc.clone();
    // 信息包
    let mut info = Vec::<u8>::new();

    let mut in_routes = Vec::new();
    // 放入本机的cidr
    in_routes.push((tun_ip, 32));
    if let Some(routes) = cfg.in_routes {
        for mut route in routes {
            route = route_with_mask(route);
            in_routes.push(split_addr(&route));
        }
    }
    let mi: MetaInfo = MetaInfo{
        in_routes4: in_routes,
    };
    serde_yaml::to_writer(&mut info, &mi).unwrap();
    cipher.encrypt_in_place(nonce, b"", &mut info).unwrap();

    let info_len = info.len();
    info.extend_from_slice(&tun_ip.octets());
    info.extend_from_slice(&u16::to_be_bytes(info_len as u16));
    info.push(bvcommon::TYPE_INFO);


    let mut _cipher = cipher.clone();
    let _info = info.clone();
    let _ = tokio::spawn(async move {
        _soc.send(&_info).await.unwrap();
        // 上次心跳时间
        let mut last_hart = Instant::now();
        let mut buf = Vec::with_capacity(4096);
        while RUNNING.load(Ordering::Relaxed) {
            let _now = Instant::now();
            if _now.duration_since(last_hart).as_secs() > 60 {
                // 发送心跳
                last_hart = _now;
                _ = _soc.send(&hart_buf).await;
                log::info!("hart to server.");
            }
            unsafe {
                buf.set_len(0);
            }
            match timeout(tokio::time::Duration::from_secs(1), rdev.read_buf(&mut buf)).await {
                Ok(_readr) => {
                    if let Ok(_) = _readr {
                        let dst = match ip::version(&buf) {
                            ip::Version::V4(_, dst) => {
                                // 拒绝组播、多播udp，仅支持单播
                                if (dst.octets()[0] >= 224 && dst.octets()[0] <= 239) || dst.octets()[3] == 255
                                {
                                    continue;
                                }
                                dst
                            }
                            _ => {
                                continue;
                            }
                        };
                        if let Ok(()) = _cipher.encrypt_in_place(nonce, b"", &mut buf) {
                            let alen = buf.len();
                            buf.extend_from_slice(&dst.octets());
                            buf.extend_from_slice(&u16::to_be_bytes(alen as u16));
                            buf.push(bvcommon::TYPE_IPV4);
                            _ = _soc.send(&buf).await;
                        }
                    }
                }
                Err(_) => {
                }
            }
        }
    });

    let _soc = soc.clone();
    let _info = info.clone();
    let _ = tokio::spawn(async move {
        let mut buf = Vec::with_capacity(4096);
        let mut last_hart = Instant::now();
        while RUNNING.load(Ordering::Relaxed) {
            let _now = Instant::now();
            if _now.duration_since(last_hart).as_secs() > 120 {
                // 超过2分钟未收到回包 发送info包重新注册
                log::info!("2 min no back.");
                _ = _soc.send(&_info).await;
            }
            unsafe {
                buf.set_len(0);
            }
            match timeout(tokio::time::Duration::from_secs(1), soc.recv_buf(&mut buf)).await {
                Ok(Ok(_)) => {
                    let alen: usize = buf.len();
                    match buf[alen - 1] {
                        bvcommon::TYPE_HARTB => {
                            // 心跳响应包
                            log::info!("hart back.");
                            last_hart = Instant::now();
                        }
                        bvcommon::TYPE_RST => {
                            // reset包
                            let _ = _soc.send(&_info).await;
                        }
                        bvcommon::TYPE_IPV4 => {
                            // ipv4包
                            if alen < 7 {
                                continue;
                            }
                            let plen = u16::from_be_bytes([buf[alen - 3], buf[alen - 2]]);
                            unsafe {
                                buf.set_len(plen as usize);
                            }
                            if let Ok(()) = cipher.decrypt_in_place(nonce, b"", &mut buf) {
                                wdev.write_all(&buf).await.unwrap();
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Err(e)) => {
                    log::info!("{} recv error {}", line!(), e);
                }
                Err(_) => {
                }
            }
        }
        _ = wdev.shutdown().await;
    });
    log::info!("ctrl + c to stop.");
    _ = tokio::signal::ctrl_c().await;
    // log::info!("stopping.");
    // RUNNING.store(false, Ordering::Relaxed);
    // _ = th1.await;
    // _ = th2.await;
}
