#[no_mangle]
pub extern "C" fn fast_mod(x: u64, y: u64) -> u64 {
    x % y
}
