
pub struct Delay {
    last_time: tokio::time::Instant,
    step: u64,
}

impl Delay {
    pub fn new() -> Self {
        Delay {
            last_time: tokio::time::Instant::now(),
            step: 1,
        }
    }

    pub async fn delay(&mut self) {
        let mut step = self.step;
        let last_time = self.last_time;
        let split_time = last_time.elapsed().as_secs();
        if split_time > 60 {
            // 1 min 重置
            step = 1;
        }
        log::info!("waite for {} secs.", step);
        tokio::time::sleep(tokio::time::Duration::from_secs(step)).await;
        // 指数退让
        step <<= 1;
        self.last_time = tokio::time::Instant::now();
        self.step = step;
    }
}