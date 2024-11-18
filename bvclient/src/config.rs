use std::net::Ipv4Addr;
use std::{fs::File, io::Read};
use serde::{Deserialize, Serialize};


/**
 * 传输基础信息
 */
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetaInfo {
    // 允许的入方向路由
    pub in_routes4: Vec<(Ipv4Addr, u8)>
}



#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CipherConfig {
    pub key: String,
    pub nonce: String,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TunConfig {
    pub ip: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RelayConfig {
    pub relay: String,
    pub salt: String,
    #[serde(rename = "group-id")]
    pub group_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DirectConfig {
    pub server: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(rename = "cipher-config")]
    pub cipher_config: CipherConfig,
    #[serde(rename = "relay-config")]
    pub relay_config: Option<RelayConfig>,
    #[serde(rename = "direct-config")]
    pub direct_config: Option<DirectConfig>,
    #[serde(rename = "in-routes")]
    pub in_routes: Option<Vec<String>>,
    #[serde(rename = "out-routes")]
    pub out_routes: Option<Vec<String>>,
    pub tun: TunConfig,
}

impl Config {
    pub fn from_file(filename: &str) -> Self {
        let f = File::open(filename);
        match f {
            Ok(mut file) => {
                let mut c = String::new();
                file.read_to_string(&mut c).unwrap();
                let cfg: Config = serde_yaml::from_str(&c).unwrap();
                cfg
            }
            Err(e) => {
                panic!("error {}", e)
            }
        }
    }
}
