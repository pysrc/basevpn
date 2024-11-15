use std::net::SocketAddr;

use tokio::net::lookup_host;


pub async fn get_one_addr(host: &str) -> Option<SocketAddr> {
    for addr in lookup_host(host).await.unwrap() {
        return Some(addr);
    }
    return None;
}
