use std::{fs::File, io::Read};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CipherConfig {
    pub key: String,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RelayConfig {
    pub relay: String,
    pub salt: String,
    #[serde(rename = "group-id")]
    pub group_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TunConfig {
    pub ip: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DirectConfig {
    pub bind: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(rename = "cipher-config")]
    pub cipher_config: CipherConfig,
    // tun配置
    pub tun: TunConfig,
    // 中继配置
    #[serde(rename = "relay-config")]
    pub relay_config: Option<RelayConfig>,
    // 直连配置
    #[serde(rename = "direct-config")]
    pub direct_config: Option<DirectConfig>,
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
