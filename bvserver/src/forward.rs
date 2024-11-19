use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::{atomic::{AtomicBool, Ordering}, Arc}};

use bytes::{Bytes, BytesMut};
use tokio::{net::UdpSocket, sync::{mpsc::{self, error::TrySendError}, RwLock}, time::Instant};

use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use treebitmap::IpLookupTable; // 使用 ChaCha20-Poly1305 实现

use crate::{buffer::PBuffer, config::{Config, MetaInfo}, ip, NONCE};

/**
 * bind: 绑定地址
 * onece: 是否一次性连接
 */
pub async fn forever(
    bind: SocketAddr, 
    cfg: Config,
    onece: bool, 
    customer_sender_map: Arc<RwLock<HashMap<IpAddr, (SocketAddr, Instant, mpsc::Sender<Bytes>, MetaInfo)>>>,
    iptables: Arc<RwLock<IpLookupTable<Ipv4Addr, Ipv4Addr>>>,
) {
    let running = Arc::new(AtomicBool::new(true));
    // 1. 初始化密钥和 nonce（随机数）
    let _k = cfg.cipher_config.key.clone();
    
    let key = Key::from_slice(_k.as_bytes()); // 密钥长度必须是 32 字节
    let nonce = unsafe { Nonce::from_slice(NONCE.as_bytes()) }; // 12 字节的 nonce

    // 2. 创建加密器实例
    let mut cipher = ChaCha20Poly1305::new(key);

    let soc = UdpSocket::bind(bind).await.unwrap();
    let soc = Arc::new(soc);
    while running.load(Ordering::Relaxed) {
        let mut buf = BytesMut::with_capacity(2000);
        let (_, addr) = match soc.recv_buf_from(&mut buf).await {
            Ok(x) => x,
            Err(e) if e.kind() == tokio::io::ErrorKind::WouldBlock => {
                // 没有数据可读，可以在这里处理或者简单地忽略
                log::info!("nodata to read.");
                continue;
            },
            Err(e) => {
                log::info!("{} soc err {}", line!(), e);
                continue;
            }
        };
        let mut pb = PBuffer::new(buf);
        if let Err(_) = cipher.decrypt_in_place(nonce, b"", &mut pb) {
            continue;
        }
        buf = pb.into_buffer();
        // 接收客户端数据包
        // 检查源地址是否存
        let (src, dst) = match ip::version(&buf) {
            ip::Version::V4(src, dst) => {
                (IpAddr::V4(src), IpAddr::V4(dst))
            }
            _ => {
                continue;
            }
        };

        if dst.is_unspecified() {
            if buf.len() <= 20 {
                // 心跳包
                // 更新心跳时间
                log::info!("hart [{}].", src);
                match customer_sender_map.write().await.get_mut(&src) {
                    Some((_org_addr, _t, _, _)) => {
                        if _org_addr != &addr {
                            // 地址发生变化
                            log::info!("{} socket address change {} -> {}", line!(), _org_addr, addr);
                            *_org_addr = addr;
                        }
                        *_t = Instant::now();
                        let mut pb = PBuffer::new(buf);
                        cipher.encrypt_in_place(nonce, b"", &mut pb).unwrap();
                        let buf = pb.into_buffer();
                        let _ = soc.try_send_to(&buf, addr);
                    }
                    None => {
                        log::info!("send reset[{}].", src);
                        // 立即重置
                        buf[16] = 127;
                        let mut pb = PBuffer::new(buf);
                        cipher.encrypt_in_place(nonce, b"", &mut pb).unwrap();
                        let buf = pb.into_buffer();
                        let _ = soc.try_send_to(&buf, addr);
                    }
                }
                continue;
            } else {
                // reset包
                let (sender, mut receiver) = mpsc::channel::<Bytes>(100);
                if let Ok(meta_info) = serde_yaml::from_slice::<MetaInfo>(&buf[20..]) {
                    log::info!("client meta info: {:?}", meta_info);
                    {
                        let mut m = iptables.write().await;
                        for (ip, masklen) in &meta_info.in_routes4 {
                            if let IpAddr::V4(addr) = src {
                                m.insert(*ip, *masklen as u32, addr);
                            }
                        }
                    }
                    let old = customer_sender_map.write().await.insert(src, (addr, Instant::now(), sender, meta_info));
                    if let Some(_) = old {
                        log::info!("{} break old client {}", line!(), src);
                    }
                } else {
                    continue;
                }
                let _soc = soc.clone();
                let mut _cipher = cipher.clone();
                let mut _running = running.clone();
                let _customer_sender_map = customer_sender_map.clone();
                tokio::spawn(async move {
                    // 接收tun设备的数据包
                    loop {
                        let buf = match receiver.recv().await {
                            Some(_buf) => _buf,
                            None => {
                                log::info!("{} close stream.", line!());
                                if onece {
                                    _running.store(false, Ordering::Relaxed);
                                }
                                return;
                            }
                        };
                        let mbuf = buf.try_into_mut().unwrap();
                        let mut pb = PBuffer::new(mbuf);
                        _cipher.encrypt_in_place(nonce, b"", &mut pb).unwrap();
                        let buf = pb.into_buffer();
                        // 拿最新地址
                        if let Ok(x) = _customer_sender_map.try_read() {
                            match x.get(&src) {
                                Some((_addr, _, _, _)) => {
                                    match _soc.try_send_to(&buf, *_addr) {
                                        Ok(_) => {}
                                        Err(ref e) if e.kind() == tokio::io::ErrorKind::WouldBlock => {
                                            // Writable false positive.
                                            log::info!("{} continue stream -> {}", line!(), e);
                                            continue;
                                        }
                                        Err(e) => {
                                            log::info!("{} close stream -> {}", line!(), e);
                                            if onece {
                                                _running.store(false, Ordering::Relaxed);
                                            }
                                            return;
                                        }
                                    }
                                }
                                None => {
                                    log::info!("{} close stream", line!());
                                    if onece {
                                        _running.store(false, Ordering::Relaxed);
                                    }
                                    return;   
                                }
                            }
                        }
                    }
                });
            }
        } else {
            // 正常数据包
            // 判断目标地址
            match dst {
                IpAddr::V4(dst4) => {
                    match iptables.try_read() {
                        Ok(_iptables) => {
                            match _iptables.longest_match(dst4) {
                                Some((_, _, toaddr)) => {
                                    let to = IpAddr::V4(*toaddr);
                                    // log::info!("{} send to {} -> {} by {}", line!(), src, dst, to);
                                    match customer_sender_map.read().await.get(&to) {
                                        Some((_, _, c, _)) => {
                                            match c.try_send(buf.freeze()) {
                                                Ok(()) => {}
                                                Err(TrySendError::Closed(_)) => {
                                                    // 通道关闭
                                                    log::info!("{} channel closed.", line!());
                                                }
                                                Err(TrySendError::Full(_)) => {
                                                    // 队列满了，直接丢弃
                                                    log::info!("{} channel full.", line!());
                                                }
                                            }
                                        }
                                        None => {
                                            log::info!("unclear {} -> {}", src, dst);
                                        }
                                    }
                                }
                                None => {
                                    continue;
                                }
                            }
                        }
                        Err(_) => {
                            continue;
                        }
                    }       
                }
                _ => {
                    log::info!("ipv6 todo");
                }
            }
        }
    }
    log::info!("break forever.");
}