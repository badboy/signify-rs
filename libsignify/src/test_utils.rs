/// A RNG that produces numbers by incrementing a value each time.
///
/// Used as a fill-in for `OsRng` since it doesn't work well for the no_std tests :(
pub struct StepperRng {
    current: u64,
}

impl Default for StepperRng {
    fn default() -> Self {
        Self { current: 5 }
    }
}

// :)
impl rand_core::CryptoRng for StepperRng {}

impl rand_core::RngCore for StepperRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let out = self.current;
        self.current = self.current.wrapping_add(1);
        out
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
