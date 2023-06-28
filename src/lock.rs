#[no_mangle]
pub extern "C" fn lock(io_lock: *mut libc::c_void) -> libc::c_int {
    1
}

#[no_mangle]
pub extern "C" fn unlock(io_lock: *mut libc::c_void) -> libc::c_int {
    1
}

#[no_mangle]
pub extern "C" fn create_lock() -> *mut libc::c_void {
    1 as *mut libc::c_void
}

#[no_mangle]
pub extern "C" fn free_lock(io_lock: *mut libc::c_void) {}
