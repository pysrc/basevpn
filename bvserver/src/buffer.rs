use bytes::BytesMut;
use chacha20poly1305::aead;


pub struct PBuffer {
    buf: BytesMut   
}


impl PBuffer {
    // 构造函数
    pub fn new(buf: BytesMut) -> Self {
        Self { buf }
    }
    pub fn into_buffer(self) -> BytesMut {
        self.buf
    }
}

// 实现 AsRef<[u8]>，提供只读访问
impl AsRef<[u8]> for PBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

// 实现 AsMut<[u8]>，提供可变访问
impl AsMut<[u8]> for PBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl aead::Buffer for PBuffer {
    fn len(&self) -> usize {
        self.buf.len()
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.buf.extend_from_slice(other);
        Ok(())
    }
    
    fn truncate(&mut self, len: usize) {
        self.buf.truncate(len);
    }
}