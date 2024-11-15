use std::net::Ipv4Addr;

pub enum Version {
    V4,
    V6,
    Others,
}
// 版本
pub fn version(buf: &[u8]) -> Version {
    if buf.len() == 0 {
        return Version::Others;
    }
    match buf[0] >> 4 {
        4 => Version::V4,
        6 => Version::V6,
        _ => Version::Others,
    }
}

// pub fn source4(buf: &[u8]) -> Ipv4Addr {
//     Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15])
// }
pub fn destination4(buf: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19])
}

