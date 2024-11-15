use std::{
    net::{Ipv4Addr, SocketAddr}, str::FromStr, sync::{atomic::{AtomicBool, Ordering}, Arc}
};

use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // 使用 ChaCha20-Poly1305 实现
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::UdpSocket, time::{self, timeout}};
use tun::AbstractDevice;

use crate::{ config, ip};


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

    // 处理tun设备
    log::info!("ip address is {}", cfg.tun.ip);
    let ipp: Vec<&str> =  cfg.tun.ip.split('/').collect();
    let prefix = u8::from_str(ipp.get(1).unwrap()).unwrap();
    let tun_ip: Ipv4Addr = Ipv4Addr::from_str(ipp.get(0).unwrap()).expect("error tun ip");
    let mut config = tun::Configuration::default();
    config
        .tun_name(&cfg.tun.name)
        .address(tun_ip)
        .netmask(prefix2mask(prefix))
        .mtu(tun::DEFAULT_MTU)
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
        if let Some(routes) = cfg.routes {
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
        if let Some(routes) = cfg.routes {
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

    let size = dev.mtu().unwrap() as usize + tun::PACKET_INFORMATION_LENGTH;
    let (mut rdev, mut wdev) = tokio::io::split(dev);

    // 同步本机信息ip
    let mut _buf = Vec::with_capacity(4);
    _buf.extend_from_slice(&tun_ip.octets());
    _buf.push(1);
    cipher.encrypt_in_place(nonce, b"", &mut _buf).unwrap();
    soc.send(&_buf).await.unwrap();
    // 接收响应信息
    let mut rbuf = Vec::new();
    let mut i = 0;
    while  i < 10 {
        rbuf.clear();
        match timeout(time::Duration::from_secs(1), soc.recv_buf(&mut rbuf)).await {
            Ok(_res) => {
                if let Err(e) = _res {
                    log::error!("{}->{}", line!(), e);
                    i += 1;
                    soc.send(&_buf).await.unwrap();
                    time::sleep(time::Duration::from_secs(1)).await;
                } else {
                    // 获取到服务器响应
                    match cipher.decrypt_in_place(nonce, b"", &mut rbuf) {
                        Ok(()) => {
                            if rbuf.last() == Some(&1) {
                                // 成功
                                unsafe {
                                    rbuf.set_len(rbuf.len() - 1);
                                }
                                log::info!("{}", String::from_utf8_lossy(&rbuf));
                                break;
                            } else {
                                log::info!("server back fail.");
                                unsafe {
                                    rbuf.set_len(rbuf.len() - 1);
                                }
                                log::info!("{}", String::from_utf8_lossy(&rbuf));
                                return;
                            }
                        }
                        Err(e) => {
                            log::error!("{}->{}", line!(), e);
                            i += 1;
                            soc.send(&_buf).await.unwrap();
                            time::sleep(time::Duration::from_secs(1)).await;
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("{}->{}", line!(), e);
                soc.send(&_buf).await.unwrap();
                i += 1;
                time::sleep(time::Duration::from_secs(1)).await;
            }
        }
    }



    let soc = Arc::new(soc);

    let _soc = soc.clone();
    let mut _cipher = cipher.clone();
    let th1 = tokio::spawn(async move {
        let mut buf = Vec::with_capacity(size);
        while RUNNING.load(Ordering::Relaxed) {
            unsafe {
                buf.set_len(0);
            }
            rdev.read_buf(&mut buf).await.unwrap();
            match ip::version(&buf) {
                ip::Version::V4 => {
                    let dst_addr = ip::destination4(&buf);
                    // 拒绝组播、多播udp，仅支持单播
                    if (dst_addr.octets()[0] >= 224 && dst_addr.octets()[0] <= 239) || dst_addr.octets()[3] == 255
                    {
                        continue;
                    }
                    buf.push(2);
                    if let Ok(()) = _cipher.encrypt_in_place(nonce, b"", &mut buf) {
                        _soc.send(&buf).await.unwrap();
                    }
                }
                _=>{}
            }
        }
    });
    let th2 = tokio::spawn(async move {
        let mut buf = Vec::with_capacity(size);
        while RUNNING.load(Ordering::Relaxed) {
            unsafe {
                buf.set_len(0);
            }
            soc.recv_buf(&mut buf).await.unwrap();
            if let Ok(()) = cipher.decrypt_in_place(nonce, b"", &mut buf) {
                if buf.last() == Some(&2) {
                    unsafe {
                        buf.set_len(buf.len() - 1);
                    }
                    wdev.write_all(&buf).await.unwrap();
                }
            }
        }
        _ = wdev.shutdown().await;
    });
    log::info!("ctrl + c to stop.");
    _ = tokio::signal::ctrl_c().await;
    log::info!("stopping.");
    RUNNING.store(false, Ordering::Relaxed);
    _ = th1.await;
    _ = th2.await;
}
