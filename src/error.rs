pub const IFD_SUCCESS: libc::c_int = 0;
pub const IFD_ERROR_TAG: libc::c_int = 600;
pub const IFD_ERROR_NOT_SUPPORTED: libc::c_int = 606;
pub const IFD_COMMUNICATION_ERROR: libc::c_int = 612;
pub const IFD_NOT_SUPPORTED: libc::c_int = 614;
pub const IFD_ERROR_INSUFFICIENT_BUFFER: libc::c_int = 618;
pub const IFD_ICC_PRESENT: libc::c_int = 615;
pub const IFD_ICC_NOT_PRESENT: libc::c_int = 616;

pub const IFD_POWER_UP: libc::c_ulong = 500;
pub const IFD_POWER_DOWN: libc::c_ulong = 501;
pub const IFD_RESET: libc::c_ulong = 502;
