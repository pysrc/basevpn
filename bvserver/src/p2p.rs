use std::{net::{Ipv4Addr, SocketAddr, SocketAddrV4}, str::FromStr};
use sha1::Digest;
use tokio::{net::UdpSocket, select};

use crate::{config::RelayConfig, netaddr};




pub async fn get_peer_addr(cfg: RelayConfig) -> Option<(SocketAddr, SocketAddr)> {
    // 向relay注册，申请打洞
    let mut hasher = sha1::Sha1::new();
    hasher.update(cfg.group_id.as_bytes());
    let ghash = hasher.finalize_reset();
    let gphash = ghash.as_slice();
    log::info!("GROUP {:?}", gphash);
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
    let mut buffer = [0u8; 41];
    buffer[20] = 1;
    buffer[21..41].copy_from_slice(gphash);
    hasher.update(cfg.salt.as_bytes());
    hasher.update(&buffer[20..]);
    let ghash = hasher.finalize_reset();
    let ihash = ghash.as_slice();
    buffer[..20].copy_from_slice(ihash);
    let mut recv_buf = [0u8; 255];
    let relay = netaddr::get_one_addr(&cfg.relay).await.unwrap();
    // 获取对方公网地址
    if let Err(_) = socket.send_to(&buffer, relay).await {
        log::info!("relay unreachable.");
        return None;
    }
    let peer_addr = loop {
        select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {
                if let Err(_) = socket.send_to(&buffer, relay).await {
                    log::info!("relay unreachable.");
                    return None;
                }
            }
            _recv = socket.recv_from(&mut recv_buf) => match _recv {
                Ok((n, addr)) => {
                    if addr != relay {
                        log::info!("addr[{}] error.", addr);
                    }
                    if n == 2 && &recv_buf[..2] == "OK".as_bytes() {
                        log::info!("hart back.");
                        continue;
                    } else {
                        match std::str::from_utf8(&recv_buf[..n]) {
                            Ok(_addr_str) => {
                                match SocketAddr::from_str(_addr_str) {
                                    Ok(_addr) => {
                                        break _addr;
                                    }
                                    Err(e) => {
                                        log::info!("{} {}", line!(), e);
                                        return None;
                                    }
                                }
                            }
                            Err(e) => {
                                log::info!("{} {}", line!(), e);
                                return None;
                            }
                        }
                    }
                }
                Err(e) => {
                    log::info!("{} {}", line!(), e);
                    return None;
                }
            }
        }
    };
    // 尝试打洞
    log::info!("hello peer[{}].", peer_addr);
    _ = socket
        .send_to("hello".as_bytes(), peer_addr)
        .await;
    // 接收响应
    let success = select! {
        // 5秒内未完成打洞则认为失败
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
            false      
        }
        _back = socket.recv_from(&mut recv_buf) => match _back {
            Ok((n, src)) => {
                let recv = String::from_utf8_lossy(&recv_buf[..n]).to_string();
                log::info!("recv[{}] {}", src, recv);
                if recv.starts_with("hello") {
                    // 收到对方发过来的第一个数据包，对方为先手
                    // 给对方回信
                    _ = socket
                        .send_to("hear".as_bytes(), peer_addr)
                        .await;
                    true
                } else if recv.starts_with("hear") {
                    // 我方为先手
                    true
                } else {
                    false
                }
            }
            Err(_) => {
                false
            }
        }
    };

    let src = socket.local_addr().unwrap();
    _ = socket;
    if success {
        // 打洞成功
        log::info!("USE P2P");
        return Some((src, peer_addr));
    } else {
        // 打洞失败申请中继
        log::info!("FOR RELAY");
        let mut relay_buffer = [0u8; 255 + 21];
        let dsts = peer_addr.to_string();
        let dst = dsts.as_bytes();
        relay_buffer[20] = 3;
        relay_buffer[21..41].copy_from_slice(gphash);
        let _len = 41 + dst.len();
        relay_buffer[41.._len].copy_from_slice(dst);
        hasher.update(cfg.salt.as_bytes());
        hasher.update(&relay_buffer[20.._len]);
        let ghash = hasher.finalize_reset();
        let ihash = ghash.as_slice();
        relay_buffer[..20].copy_from_slice(ihash);
        _ = socket.send_to(&relay_buffer[.._len], relay).await.unwrap();
        match socket.recv_from(&mut relay_buffer).await {
            Ok((n, _)) => {
                let _back = String::from_utf8_lossy(&relay_buffer[..n]).to_string();
                if _back.starts_with("RELAY") {
                    log::info!("USE RELAY");
                    return Some((src, relay));
                } else if _back.starts_with("NORELAY") {
                    log::info!("NO RELAY");
                    return None;
                } else {
                    return None;
                }
            }
            Err(e) => {
                log::info!("{} {}", line!(), e);
                return None;
            }
        }
    }
}
