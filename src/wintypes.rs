use libc::*;

pub type DWORD = c_ulong;
pub type UCHAR = c_uchar;
pub type PUCHAR = *mut UCHAR;
pub type LPDWORD = *mut DWORD;
pub type PDWORD = *mut DWORD;
pub type LPSTR = *mut c_char;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScardIoHeader {
    pub protocol: DWORD,
    pub length: DWORD,
}

pub type PscardIoHeader = *mut ScardIoHeader;
