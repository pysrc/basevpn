use std::{
    net::{Ipv4Addr, SocketAddr}, sync::{atomic::{AtomicBool, Ordering}, Arc}
};

use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // 使用 ChaCha20-Poly1305 实现
use tokio::{net::UdpSocket, sync::mpsc, time::{timeout, Instant}};

use crate::{ buffer::PBuffer, config::{Config, MetaInfo}, ip, route_with_mask, split_addr};

static mut NONCE: String = String::new();

pub async fn forever(bind: SocketAddr, peer: SocketAddr, tun_ip: Ipv4Addr, cfg: Config, dev_sender: mpsc::Sender<Bytes>, mut soc_receiver: mpsc::Receiver<Bytes>) -> (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
    
    static RUNNING: AtomicBool = AtomicBool::new(true);

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


    // 心跳包
    let mut hart_buf = vec![0u8;5];
    hart_buf[4] = bvcommon::TYPE_HART;
    hart_buf[0..4].copy_from_slice(&tun_ip.octets());

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
    let th1 = tokio::spawn(async move {
        _soc.send(&_info).await.unwrap();
        // 上次心跳时间
        let mut last_hart = Instant::now();
        while RUNNING.load(Ordering::Relaxed) {
            let _now = Instant::now();
            if _now.duration_since(last_hart).as_secs() > 60 {
                // 发送心跳
                last_hart = _now;
                _ = _soc.send(&hart_buf).await;
                log::info!("hart to server.");
            }
            match timeout(tokio::time::Duration::from_secs(1), soc_receiver.recv()).await {
                Ok(_readr) => {
                    if let Some(buf) = _readr {
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

                        let buf = BytesMut::from(buf);
                        let mut pb = PBuffer::new(buf);
                        _cipher.encrypt_in_place(nonce, b"", &mut pb).unwrap();
                        let mut buf = pb.into_buffer();
                        let alen = buf.len();
                        buf.extend_from_slice(&dst.octets());
                        buf.extend_from_slice(&u16::to_be_bytes(alen as u16));
                        buf.put_u8(bvcommon::TYPE_IPV4);
                        if let Err(e) = _soc.send(&buf).await {
                            log::info!("{} -> {}", line!(), e);
                            // soc异常
                            RUNNING.store(false, Ordering::Relaxed);
                            return soc_receiver;
                        }
                    }
                }
                Err(_) => {
                }
            }
        }
        return soc_receiver;
    });

    let _soc = soc.clone();
    let _info = info.clone();
    let mut _cipher = cipher.clone();
    let th2 = tokio::spawn(async move {
        let mut last_hart = Instant::now();
        while RUNNING.load(Ordering::Relaxed) {
            let mut buf = BytesMut::with_capacity(4096);
            let _now = Instant::now();
            if _now.duration_since(last_hart).as_secs() > 120 {
                // 超过2分钟未收到回包 发送info包重新注册
                log::info!("2 min no back.");
                if let Err(e) = _soc.send(&_info).await {
                    log::info!("{} -> {}", line!(), e);
                    RUNNING.store(false, Ordering::Relaxed);
                    return dev_sender;
                }
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

                            let mut pb = PBuffer::new(buf);
                            if let Ok(_) = _cipher.decrypt_in_place(nonce, b"", &mut pb) {
                                let buf = pb.into_buffer();
                                let _ = dev_sender.try_send(buf.freeze());
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
        return dev_sender;
    });

    let soc_receiver = th1.await.unwrap();
    let dev_sender = th2.await.unwrap();
    (dev_sender, soc_receiver)
}
