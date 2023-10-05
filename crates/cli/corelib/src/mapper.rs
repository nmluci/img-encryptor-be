use std::usize;

pub fn vec_to_arr<const U: usize>(v: Vec<u8>) -> [u8; U] {
    let mut buf = [0u8; U];
    buf[..U].copy_from_slice(&v);
    buf
 }