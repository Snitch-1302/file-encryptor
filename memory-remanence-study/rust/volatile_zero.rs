use std::hint::black_box;
use std::ptr;

#[unsafe(no_mangle)]
pub extern "C" fn derive_and_wipe_volatile() {
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = i as u8;
    }

    black_box(&key);

    for i in 0..32 {
        unsafe {
            ptr::write_volatile(&mut key[i], 0);
        }
    }
}