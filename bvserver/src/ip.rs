use std::net::Ipv4Addr;

#[allow(dead_code)]
pub enum Version {
    V4(Ipv4Addr, Ipv4Addr),
    Others,
}
// 版本
pub fn version(buf: &[u8]) -> Version {
    if buf.len() == 0 {
        return Version::Others;
    }
    match buf[0] >> 4 {
        4 => Version::V4(source4(buf), destination4(buf)),
        _ => Version::Others,
    }
}

fn source4(buf: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15])
}

fn destination4(buf: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19])
}

