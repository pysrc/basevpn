use std::{collections::HashMap, net::{IpAddr, SocketAddr}, sync::{atomic::{AtomicBool, Ordering}, Arc}};

use tokio::{net::UdpSocket, sync::{mpsc::{self, error::TrySendError}, RwLock}};

use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // 使用 ChaCha20-Poly1305 实现

use crate::{config::Config, ip, VecPool, NONCE};

/**
 * bind: 绑定地址
 * tls_key: tls密钥
 * tls_cert: tls公钥
 * onece: 是否一次性连接
 */
pub async fn forever(
    bind: SocketAddr, 
    cfg: Config,
    onece: bool, 
    main_sender: mpsc::Sender<Vec<u8>>, 
    customer_sender_map: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<Vec<u8>>>>>,
    r2vmap: Arc<RwLock<HashMap<SocketAddr, IpAddr>>>,
    mut pool: VecPool,
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
        let mut buf = pool.pop_without_size().await;
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
        if let Err(_) = cipher.decrypt_in_place(nonce, b"", &mut buf) {
            pool.back(buf).await;
            continue;
        }
        // 接收客户端数据包
        // 检查源地址是否存
        let (src, _) = match ip::version(&buf) {
            ip::Version::V4(src, dst) => {
                (IpAddr::V4(src), IpAddr::V4(dst))
            }
            _ => {
                pool.back(buf).await;
                continue;
            }
        };
        // 客户端地址是否存在
        if !r2vmap.read().await.contains_key(&addr) || !customer_sender_map.read().await.contains_key(&src) {
            // 新客户端接入
            log::info!("client ip is: {}", src);
            let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(100);
            let old = customer_sender_map.write().await.insert(src, sender);
            if let Some(_old) = old {
                log::info!("{} break old client {}", line!(), src);
            }
            // 移除老的
            r2vmap.write().await.retain(|_, v| v != &src);
            r2vmap.write().await.insert(addr, src);
            let _customer_sender_map = customer_sender_map.clone();
            let _soc = soc.clone();
            let mut _pool = pool.clone();
            let mut _cipher = cipher.clone();
            let mut _running = running.clone();
            tokio::spawn(async move {
                // 接收tun设备的数据包
                loop {
                    let mut buf = match receiver.recv().await {
                        Some(_buf) => _buf,
                        None => {
                            log::info!("{} close stream.", line!());
                            if onece {
                                _running.store(false, Ordering::Relaxed);
                            }
                            return;
                        }
                    };
                    _cipher.encrypt_in_place(nonce, b"", &mut buf).unwrap();
                    // log::info!("{}: {}->{}", line!(), _soc.local_addr().unwrap(), addr);
                    if let Err(_) = _soc.send_to(&buf, addr).await {
                        log::info!("{} close stream.", line!());
                        if onece {
                            _running.store(false, Ordering::Relaxed);
                        }
                        return;
                    }
                    _pool.back(buf).await;
                }
            });
        }
        match main_sender.try_send(buf) {
            Ok(()) => {}
            Err(TrySendError::Closed(message)) => {
                // 主通道关闭
                log::info!("{} channel closed.", line!());
                pool.back(message).await;
                return;
            }
            Err(TrySendError::Full(message)) => {
                // 队列满了，直接丢弃
                log::info!("{} channel full.", line!());
                pool.back(message).await;
            }
        }
    }
    log::info!("break forever.");
}