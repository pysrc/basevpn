use std::{fs::File, io::Write, net::{IpAddr, Ipv4Addr, SocketAddr}, str::FromStr};

use clap::Parser;

mod p2p;
mod config;
mod netaddr;
mod forward;
mod ip;
/// Config
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path of the config file
    #[arg(short, long, default_value_t = String::from_str("bvclient-config.yml").unwrap())]
    config: String,
}

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



    let rcfg = cfg.relay_config.clone();
    match rcfg {
        Some(rcfg) => {
            let peer_info = p2p::get_peer_addr(rcfg).await;
            match peer_info {
                Some((_bind, _peer)) => {
                    log::info!("start relay mode.");
                    forward::forever(_bind, _peer, cfg.clone()).await;
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
                    let peer = netaddr::get_one_addr(&dcfg.server).await.unwrap();
                    forward::forever(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), peer, cfg).await;
                }
                None => {
                    log::info!("STOP.");
                }
            }
        }
    }
    
}
