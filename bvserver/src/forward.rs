use std::{collections::HashMap, net::{Ipv4Addr, SocketAddr}, sync::Arc};

use tokio::{net::UdpSocket, sync::{mpsc::{self, error::TrySendError}, RwLock}};

use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // 使用 ChaCha20-Poly1305 实现

use crate::{config::Config, VecPool, NONCE};

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
    customer_sender_map: Arc<RwLock<HashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>>>,
    mut pool: VecPool,
) {
    // 1. 初始化密钥和 nonce（随机数）
    let _k = cfg.cipher_config.key.clone();
    
    let key = Key::from_slice(_k.as_bytes()); // 密钥长度必须是 32 字节
    let nonce = unsafe { Nonce::from_slice(NONCE.as_bytes()) }; // 12 字节的 nonce

    // 2. 创建加密器实例
    let mut cipher = ChaCha20Poly1305::new(key);

    let soc = UdpSocket::bind(bind).await.unwrap();
    let soc = Arc::new(soc);
    loop {
        let mut buf = pool.pop_without_size().await;
        let (_, addr) = soc.recv_buf_from(&mut buf).await.unwrap();
        if let Err(_) = cipher.decrypt_in_place(nonce, b"", &mut buf) {
            pool.back(buf).await;
            continue;
        }
        match buf.last() {
            Some(&1) => {
                // 初始创建ip
                let client_ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                log::info!("client ip is: {}", client_ip);
                let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(100);
                let old = customer_sender_map.write().await.insert(client_ip, sender);
                if let Some(_old) = old {
                    log::info!("{} break old client {}", line!(), client_ip);
                }
                // 响应成功包
                let mut resp = b"server: hello welcome.".to_vec();
                resp.push(1);
                cipher.encrypt_in_place(nonce, b"", &mut resp).unwrap();
                if let Err(_) = soc.send_to(&resp, addr).await {
                    log::info!("{} close stream.", line!());
                    customer_sender_map.write().await.remove(&client_ip);
                    if onece {
                        return;
                    } else {
                        continue;
                    }
                }
                let _customer_sender_map = customer_sender_map.clone();
                let _soc = soc.clone();
                let mut _pool = pool.clone();
                let mut _cipher = cipher.clone();
                tokio::spawn(async move {
                    // 接收tun设备的数据包
                    loop {
                        let mut buf = match receiver.recv().await {
                            Some(_buf) => _buf,
                            None => {
                                log::info!("{} close stream.", line!());
                                _customer_sender_map.write().await.remove(&client_ip);
                                return;
                            }
                        };
                        buf.push(2);
                        _cipher.encrypt_in_place(nonce, b"", &mut buf).unwrap();
                        if let Err(_) = _soc.send_to(&buf, addr).await {
                            log::info!("{} close stream.", line!());
                            _customer_sender_map.write().await.remove(&client_ip);
                            return;
                        }
                        _pool.back(buf).await;
                    }
                });
            }
            Some(&2) => {
                // 接收客户端数据包
                unsafe {
                    buf.set_len(buf.len() - 1);
                }
                match main_sender.try_send(buf) {
                    Ok(()) => {}
                    Err(TrySendError::Closed(message)) => {
                        // 通道关闭
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
            _ => {}
        }
    }
}