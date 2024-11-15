use std::{collections::{HashMap, VecDeque}, fs::File, io::Write, net::{Ipv4Addr, SocketAddr}, str::FromStr, sync::Arc};

use clap::Parser;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::{mpsc::{self, error::TrySendError}, Mutex, RwLock}};

mod config;
mod delay;
mod p2p;
mod netaddr;
mod forward;
mod ip;

static mut NONCE: String = String::new();

#[derive(Clone)]
struct VecPool {
    vec_pool: Arc<Mutex<VecDeque<Vec<u8>>>>
}

impl VecPool {
    pub fn new(size: usize) -> Self {
        let mut _inner = VecDeque::<Vec<u8>>::with_capacity(size);
        for _ in 0..size {
            _inner.push_back(Vec::with_capacity(100));
        }
        VecPool {
            vec_pool: Arc::new(Mutex::new(_inner))
        }
    }
    pub async fn pop(&mut self, size: usize) -> Vec<u8> {
        let mut t = self.vec_pool.lock().await;
        let v = t.pop_back();
        match v {
            Some(mut d) => {
                d.resize(size, 0);
                return d;
            }
            None => {
                let mut d = Vec::with_capacity(size);
                unsafe {
                    d.set_len(size);
                }
                return d;
            }
        }
    }
    pub async fn pop_without_size(&mut self) -> Vec<u8> {
        let mut t = self.vec_pool.lock().await;
        let v = t.pop_back();
        match v {
            Some(mut d) => {
                unsafe {
                    d.set_len(0);
                }
                return d;
            }
            None => {
                let d = Vec::new();
                return d;
            }
        }
    }
    pub async fn back(&mut self, mut data: Vec<u8>) {
        if self.vec_pool.lock().await.len() > 200 {
            log::info!("vec pool more than 200.");
            return;
        }
        unsafe {
            data.set_len(0);
        }
        let mut t = self.vec_pool.lock().await;
        t.push_back(data);
    }
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

/// Config
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path of the config file
    #[arg(short, long, default_value_t = String::from_str("bvserver-config.yml").unwrap())]
    config: String,
}

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

    // 全局数据包池
    let pool = VecPool::new(10);

    // 处理tun设备
    let ipp: Vec<&str> =  cfg.tun.ip.split('/').collect();
    let prefix = u8::from_str(ipp.get(1).unwrap()).unwrap();
    let tun_ip: Ipv4Addr = Ipv4Addr::from_str(ipp.get(0).unwrap()).expect("error tun ip");
    let mut config = tun::Configuration::default();
    let mtu = tun::DEFAULT_MTU;
    config
        .tun_name(&cfg.tun.name)
        .address(tun_ip)
        .netmask(prefix2mask(prefix))
        .mtu(mtu)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    let dev = tun::create_as_async(&config).unwrap();
    
    let (mut rdev, mut wdev) = tokio::io::split(dev);

    // 主通道
    let (main_sender, mut main_receiver) = mpsc::channel::<Vec<u8>>(100);
    // 客户端通道
    let customer_sender_map = Arc::new(RwLock::new(HashMap::<Ipv4Addr, mpsc::Sender<Vec<u8>>>::new()));
    let _customer_sender_map = customer_sender_map.clone();
    let mut _pool = pool.clone();
    tokio::task::spawn(async move {
        // 虚拟网卡读
        loop {
            let mut buf = _pool.pop(mtu as usize).await;
            let len = rdev.read(&mut buf).await.unwrap();
            unsafe {
                buf.set_len(len);
            }
            // 转发到对应的目的地
            match ip::version(&buf) {
                ip::Version::V4 => {
                    let dst = ip::destination4(&buf);
                    // 拒绝组播、多播udp，仅支持单播
                    if (dst.octets()[0] >= 224 && dst.octets()[0] <= 239) || dst.octets()[3] == 255
                    {
                        _pool.back(buf).await;
                        continue;
                    }
                    let mut m = _customer_sender_map.write().await;
                    if let Some(s) = m.get_mut(&dst) {
                        match s.try_send(buf) {
                            Ok(()) => {

                            }
                            Err(TrySendError::Closed(message)) => {
                                // 通道关闭
                                log::info!("{} channel closed.", line!());
                                _ = m.remove(&dst);
                                _pool.back(message).await;
                            }
                            Err(TrySendError::Full(message)) => {
                                // 队列满了，直接丢弃
                                log::info!("{} channel full.", line!());
                                _pool.back(message).await;
                            }
                        }
                    } else {
                        _pool.back(buf).await;
                    }
                }
                _ => {
                    _pool.back(buf).await;
                }
            }
        }
    });
    let mut _pool = pool.clone();
    let _customer_sender_map = customer_sender_map.clone();
    tokio::spawn(async move {
        // 虚拟网卡写
        loop {
            let buf = main_receiver.recv().await.unwrap();
            // 目的地是否其他客户端
            match ip::version(&buf) {
                ip::Version::V4 => {
                    let dst = ip::destination4(&buf);
                    let mut m = _customer_sender_map.write().await;
                    if let Some(s) = m.get_mut(&dst) {
                        // 转发给其他客户端
                        match s.try_send(buf) {
                            Ok(()) => {}
                            Err(TrySendError::Closed(message)) => {
                                // 通道关闭
                                log::info!("{} channel closed.", line!());
                                _ = m.remove(&dst);
                                _pool.back(message).await;
                            }
                            Err(TrySendError::Full(message)) => {
                                // 队列满了，直接丢弃
                                log::info!("{} channel full.", line!());
                                _pool.back(message).await;
                            }
                        }
                    } else {
                        wdev.write_all(&buf).await.unwrap();
                        wdev.flush().await.unwrap();
                        _pool.back(buf).await;
                    }
                }
                _ => {
                    _pool.back(buf).await;
                }
            }

        }
    });

    // 中继模式
    let rcfg = cfg.relay_config.clone();
    let cfg1 = cfg.clone();
    let _main_sender = main_sender.clone();
    let _customer_sender_map = customer_sender_map.clone();
    let _pool = pool.clone();
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
                    let __pool = _pool.clone();
                    tokio::spawn(async move {
                        match peer_info {
                            Some((_bind, _)) => {
                                forward::forever(_bind, cfgc, true, __main_sender, __customer_sender_map, __pool).await;
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
                let _pool = pool.clone();
                forward::forever(bind, cfg, false, _main_sender, _customer_sender_map, _pool).await;
            }
            None => {
                log::info!("no direct config");
            }
        }
    });

    log::info!("ctrl + c to exit.");
    tokio::signal::ctrl_c().await.unwrap();
}
