use alloc::vec::Vec;

pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    #[inline(never)]
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        let mut i = 0usize;
        while i < 256 {
            s[i] = i as u8;
            i += 1;
        }

        // KSA
        let mut j: u8 = 0;
        let mut i2 = 0usize;
        while i2 < 256 {
            let key_byte = key[i2 % key.len()];
            j = j.wrapping_add(s[i2]).wrapping_add(key_byte);
            s.swap(i2, j as usize);
            i2 += 1;
        }

        Rc4 { s, i: 0, j: 0 }
    }

    #[inline(never)]
    pub fn apply(&mut self, data: &mut [u8]) {
        let mut k = 0usize;
        while k < data.len() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);

            let idx = self.s[self.i as usize]
                .wrapping_add(self.s[self.j as usize]) as usize;
            let keystream = self.s[idx];
            data[k] ^= keystream;
            k += 1;
        }
    }
}

pub struct EncryptedBytes<const N: usize> {
    pub data: [u8; N],
    pub key: [u8; 16],
}

impl<const N: usize> EncryptedBytes<N> {
    #[inline(never)]
    pub fn decrypt(&self) -> Vec<u8> {
        // allocate Vec with exact capacity
        let mut out = Vec::with_capacity(N);
        out.extend_from_slice(&self.data);

        let mut rc4 = Rc4::new(&self.key);
        rc4.apply(out.as_mut_slice());
        out
    }
}

pub const fn rc4_encrypt_const<const N: usize>(key: &[u8; 16], input: &[u8]) -> [u8; N] {
    let mut s = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        s[i] = i as u8;
        i += 1;
    }

    let mut j: u8 = 0;
    let mut i2 = 0usize;
    while i2 < 256 {
        let key_byte = key[i2 % key.len()];
        j = j.wrapping_add(s[i2]).wrapping_add(key_byte);
        let tmp = s[i2];
        s[i2] = s[j as usize];
        s[j as usize] = tmp;
        i2 += 1;
    }

    let mut out = [0u8; N];
    let mut i3: u8 = 0;
    let mut j2: u8 = 0;
    let mut k = 0usize;
    while k < N {
        i3 = i3.wrapping_add(1);
        j2 = j2.wrapping_add(s[i3 as usize]);
        let tmp = s[i3 as usize];
        s[i3 as usize] = s[j2 as usize];
        s[j2 as usize] = tmp;

        let idx = s[i3 as usize].wrapping_add(s[j2 as usize]) as usize;
        let ks = s[idx];
        out[k] = input[k] ^ ks;
        k += 1;
    }
    out
}

#[macro_export]
macro_rules! encrypt_bytes {
    ($bytes:expr) => {{
        use const_random::const_random;
        const _KEY: [u8; 16] = [
            const_random!(u8), const_random!(u8), const_random!(u8), const_random!(u8),
            const_random!(u8), const_random!(u8), const_random!(u8), const_random!(u8),
            const_random!(u8), const_random!(u8), const_random!(u8), const_random!(u8),
            const_random!(u8), const_random!(u8), const_random!(u8), const_random!(u8),
        ];
        const _RAW: &[u8] = $bytes;
        const _LEN: usize = _RAW.len();
        const _ENC: [u8; _LEN] = $crate::rc4::rc4_encrypt_const::<_LEN>(&_KEY, _RAW);

        $crate::rc4::EncryptedBytes::<{ _LEN }> {
            data: _ENC,
            key: _KEY,
        }
    }};
}