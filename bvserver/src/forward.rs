use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::{atomic::{AtomicBool, Ordering}, Arc}};

use bytes::{Bytes, BytesMut};
use tokio::{net::UdpSocket, sync::{mpsc::{self, error::TrySendError}, RwLock}, time::Instant};

use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use treebitmap::IpLookupTable; // 使用 ChaCha20-Poly1305 实现

use crate::{buffer::PBuffer, config::{Config, MetaInfo}, NONCE};

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
        if buf.len() == 0 {
            continue;
        }
        let alen = buf.len();
        match buf[alen - 1] {
            bvcommon::TYPE_HART => {
                // 心跳包
                if alen != 5 {
                    continue;
                }
                let src = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                // 更新心跳时间
                log::info!("hart [{}].", src);
                match customer_sender_map.write().await.get_mut(&IpAddr::V4(src)) {
                    Some((_org_addr, _t, _, _)) => {
                        *_t = Instant::now();
                        if _org_addr != &addr {
                            // 地址发生变化
                            log::info!("{} socket address change {} -> {}", line!(), _org_addr, addr);
                            *_org_addr = addr;
                        }
                        // 响应
                        buf[4] = bvcommon::TYPE_HARTB;
                        let _ = soc.try_send_to(&buf, addr);
                    }
                    None => {
                        log::info!("send reset[{}].", src);
                        // 立即重置
                        let _ = soc.try_send_to(&[bvcommon::TYPE_RST], addr);
                    }
                }
            }
            bvcommon::TYPE_INFO => {
                // 环境信息包
                if alen < 7 {
                    continue;
                }
                let length = u16::from_be_bytes([buf[alen - 3], buf[alen - 2]]) as usize;
                let src = Ipv4Addr::new(buf[alen - 7], buf[alen - 6], buf[alen - 5], buf[alen - 4]);
                unsafe {
                    buf.set_len(length);
                }
                // 解密数据包
                let mut pb = PBuffer::new(buf);
                if let Err(_) = cipher.decrypt_in_place(nonce, b"", &mut pb) {
                    continue;
                }
                buf = pb.into_buffer();
                
                // 重置客户端
                let (sender, mut receiver) = mpsc::channel::<Bytes>(100);
                if let Ok(meta_info) = serde_yaml::from_slice::<MetaInfo>(&buf) {
                    log::info!("client meta info: {:?}", meta_info);
                    {
                        let mut m = iptables.write().await;
                        for (ip, masklen) in &meta_info.in_routes4 {
                            m.insert(*ip, *masklen as u32, src);
                        }
                    }
                    let old = customer_sender_map.write().await.insert(IpAddr::V4(src), (addr, Instant::now(), sender, meta_info));
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
                    // 接收数据包
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
                        // 拿最新地址
                        if let Ok(x) = _customer_sender_map.try_read() {
                            match x.get(&IpAddr::V4(src)) {
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
            bvcommon::TYPE_IPV4 => {
                // ipv4信息包
                if alen < 7 {
                    continue;
                }
                let dst = Ipv4Addr::new(buf[alen - 7], buf[alen - 6], buf[alen - 5], buf[alen - 4]);
                match iptables.try_read() {
                    Ok(_iptables) => {
                        match _iptables.longest_match(dst) {
                            Some((_, _, toaddr)) => {
                                let to = IpAddr::V4(*toaddr);
                                // log::info!("{} send to {} by {}", line!(), dst, to);
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
                                        log::info!("unclear {}", dst);
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

            }
        }
    }
    log::info!("break forever.");
}