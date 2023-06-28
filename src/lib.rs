mod error;
mod lock;
mod vpcd;
mod wintypes;
use lazy_static::lazy_static;
use libc::{free, memcpy};
use socket::htonl;
use std::{borrow::BorrowMut, cell::RefCell, ffi::CString, mem, slice};

use error::*;
use vpcd::{vicc_present, vicc_transmit, PcscTlvStructure, ViccCtx};
use wintypes::*;

use crate::vpcd::{vicc_exit, vicc_getatr, vicc_init, vicc_power_off, vicc_power_on, vicc_reset};

pub const TAG_IFD_ATR: u64 = 0x0303;
pub const TAG_IFD_SLOTS_NUMBER: u64 = 0x0FAE;
pub const TAG_IFD_THREAD_SAFE: u64 = 0x0FAD;
pub const TAG_IFD_SLOT_THREAD_SAFE: u64 = 0x0FAC;

const VICC_MAX_SLOTS: libc::c_uchar = 4;

const CLASS2_IOCTL_MAGIC: libc::c_int = 0x330000;
const FEATURE_GET_TLV_PROPERTIES: libc::c_int = 0x12;
const CM_IOCTL_FEATURE_GET_TLV_PROPERTIES: libc::c_int =
    0x42000000 + (FEATURE_GET_TLV_PROPERTIES + CLASS2_IOCTL_MAGIC);
const CM_IOCTL_GET_FEATURE_REQUREST: libc::c_int = 0x42000000 + 3400;
const PCSCV2_PART10_PROPERTY_DW_MAX_APDUDATA_SIZE: libc::c_int = 10;

const HOSTNAME: *const libc::c_char = std::ptr::null();

static mut CTX: [Option<RefCell<ViccCtx>>; VICC_MAX_SLOTS as usize] = [None,None,None,None];

/*static mut CTX2: [RefCell<ViccCtx>; VICC_MAX_SLOTS as usize] = [
    RefCell::new(ViccCtx {
        server_sock: None,
        client_sock: -1,
        hostname: std::ptr::null_mut(),
        port: 0,
        io_lock: std::ptr::null_mut(),
    }),
    RefCell::new(ViccCtx {
        server_sock: None,
        client_sock: -1,
        hostname: std::ptr::null_mut(),
        port: 0,
        io_lock: std::ptr::null_mut(),
    }),
];*/

#[no_mangle]
pub extern "C" fn IFDHControl(
    lun: DWORD,
    dw_control_code: DWORD,
    tx_buffer: PUCHAR,
    txlength: DWORD,
    rx_buffer: PUCHAR,
    rx_length: DWORD,
    pdw_bytes_returned: LPDWORD,
) -> DWORD {
    if pdw_bytes_returned.is_null() {
        return IFD_COMMUNICATION_ERROR as DWORD;
    }

    if dw_control_code == CM_IOCTL_GET_FEATURE_REQUREST as DWORD {
        if rx_length < std::mem::size_of::<PcscTlvStructure>() as DWORD {
            return IFD_ERROR_INSUFFICIENT_BUFFER as DWORD;
        }

        let pcsc_tlv: *mut PcscTlvStructure = rx_buffer as *mut PcscTlvStructure;
        unsafe {
            std::ptr::write(
                &mut (*pcsc_tlv).tag as *mut u8,
                FEATURE_GET_TLV_PROPERTIES as u8,
            )
        };
        unsafe {
            std::ptr::write(
                &mut (*pcsc_tlv).lenght as *mut u8,
                std::mem::size_of::<u32>() as u8,
            )
        };

        let value = htonl(CM_IOCTL_FEATURE_GET_TLV_PROPERTIES as u32);

        /*let src_ptr = &value as *const u32 as *const u8;
        let dst_ptr = &mut ( *pcsc_tlv ).value as *mut u32 as *mut u8;
        let size = mem::size_of::<u32>();

        unsafe {
            std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size);
        }*/

        unsafe { std::ptr::write(&mut (*pcsc_tlv).value, value) };

        unsafe { *pdw_bytes_returned = std::mem::size_of::<PcscTlvStructure>() as DWORD };

        return 0;
    }

    if dw_control_code == CM_IOCTL_FEATURE_GET_TLV_PROPERTIES as u64 {
        if rx_length < 6 {
            return IFD_ERROR_INSUFFICIENT_BUFFER as DWORD;
        }

        let max_apdu_data_size: libc::c_uint = 0x10000;
        let mut p: libc::c_uint = 0;
        unsafe {
            *rx_buffer.add(p as usize) = PCSCV2_PART10_PROPERTY_DW_MAX_APDUDATA_SIZE as u8;
            p += 1;
            *rx_buffer.add(p as usize) = 4;
            p += 1;
            let max_apdu_data_size_bytes = max_apdu_data_size.to_be_bytes();
            for byte in &max_apdu_data_size_bytes {
                *rx_buffer.add(p.try_into().unwrap()) = *byte;
                p += 1;
            }
        }
        unsafe { *pdw_bytes_returned = p as u64 };

        return 0;
    }

    unsafe { *pdw_bytes_returned = 0 };
    return IFD_ERROR_NOT_SUPPORTED as DWORD;
}

#[no_mangle]
pub extern "C" fn IFDHCreateChannel(lun: DWORD, channel: DWORD) -> DWORD {
    let slot: libc::c_ulong = lun & 0xffff; // 0

    if slot >= VICC_MAX_SLOTS.into() {
        return IFD_COMMUNICATION_ERROR as DWORD;
    }

    if HOSTNAME.is_null() {
        unsafe {
            CTX[slot as usize] = Some(vicc_init(HOSTNAME, (channel + slot) as libc::c_ushort));
        }
    }

    0
}

#[no_mangle]
pub extern "C" fn IFDHCloseChannel(lun: DWORD) -> DWORD {
    let slot: libc::c_ulong = lun & 0xffff; // 0

    if slot > VICC_MAX_SLOTS as u64 {
        return IFD_COMMUNICATION_ERROR as libc::c_ulong;
    }
    let ctx = unsafe { &mut CTX };

    let context = &mut ctx[slot as usize];

    if vicc_exit(context) < 0 {
        println!("COULD NOT CLOSE CONNECTION TO VIRTUAL ICC");
        return IFD_COMMUNICATION_ERROR as libc::c_ulong;
    }


    unsafe {
        CTX[slot as usize] = None;
    }

    0
}

#[no_mangle]
pub extern "C" fn IFDHGetCapabilities(
    lun: DWORD,
    tag: DWORD,
    length: PDWORD,
    value: PUCHAR,
) -> DWORD {

    let mut result = IFD_COMMUNICATION_ERROR as DWORD;
    let mut size: libc::ssize_t = 0;
    let mut atr: *mut libc::c_uchar = std::ptr::null_mut();
    let slot: libc::c_ulong = lun & 0xffff; // 0

    if slot > VICC_MAX_SLOTS as u64 {
        if result != IFD_SUCCESS as DWORD && !length.is_null() {
            unsafe { *length = 0 };
            return result;
        }
    }

    if length.is_null() || value.is_null() {
        if result != IFD_SUCCESS as DWORD && !length.is_null() {
            unsafe { *length = 0 };
            return result;
        }
    }

    let ctx = unsafe { &mut CTX };

    let context = match &mut ctx[slot as usize] {
        Some(value) => value,
        None => {
            if result != IFD_SUCCESS as DWORD && !length.is_null() {
                unsafe { *length = 0 };
            }
            println!("COULD NOT GET CTX");
            return result;
        }
    };


    match tag {
        TAG_IFD_ATR => {
            println!("MATCHED TAG_IFD_ATR");
            size = vicc_getatr(context, &mut atr);
            unsafe { *length = size as u64 };

            //let valuee = atr[..].as_ptr() as PUCHAR;
            unsafe{memcpy(value as *mut libc::c_void, atr as *mut libc::c_void, size as usize);}
            //unsafe { *value = *atr };
        }
        TAG_IFD_SLOTS_NUMBER => {
            println!("MATCHED TAG_IFD_SLOTS_NUMBER");
            if unsafe { *length } < 1 {
                if result != IFD_SUCCESS as DWORD && !length.is_null() {
                    unsafe { *length = 0 };
                    return result;
                }
            }
            /* We are not thread safe due to
             * the global hostname and ctx */
            unsafe { *value = VICC_MAX_SLOTS };
            unsafe { *length = 1 };
            return IFD_SUCCESS as DWORD;
        }
        TAG_IFD_THREAD_SAFE => {
            println!("MATCHED TAG_IFD_THREAD_SAFE");
            unsafe { *value = 0 };
            unsafe { *length = 1 };
        }
        TAG_IFD_SLOT_THREAD_SAFE => {
            /* driver supports access to multiple slots of the same reader at
             * the same time VALUE = 1 */
            println!("MATCHED TAG_IFD_SLOT_THREAD_SAFE");
            unsafe { *value = 0 };
            unsafe { *length = 1 };
        }
        _ => {
            println!("UNKNOWN TAG {:#?}", &tag);
            result = IFD_ERROR_TAG as DWORD;
        }
    }

    result
}

#[no_mangle]
pub extern "C" fn IFDHSetCapabilities(
    lun: DWORD,
    tag: DWORD,
    length: PDWORD,
    value: PUCHAR,
) -> DWORD {
    IFD_NOT_SUPPORTED as DWORD
}

#[no_mangle]
pub extern "C" fn IFDHSetProtocolParameters(
    lun: DWORD,
    protocol: DWORD,
    flags: UCHAR,
    pts1: UCHAR,
    pts2: UCHAR,
    pts3: UCHAR,
) -> DWORD {
    IFD_SUCCESS as DWORD
}

#[no_mangle]
pub extern "C" fn IFDHPowerICC(
    lun: DWORD,
    action: DWORD,
    atr: PUCHAR,
    atr_length: PDWORD,
) -> DWORD {
    let slot: libc::c_ulong = lun & 0xffff;

    let mut result = IFD_COMMUNICATION_ERROR as DWORD;

    if slot > VICC_MAX_SLOTS as u64 {
        //handle error
        if result != IFD_SUCCESS as DWORD && unsafe { *atr_length } != 0 {
            unsafe { *atr_length = 0 };
            return result;
        } else {
            result = IFDHGetCapabilities(lun, TAG_IFD_ATR, atr_length, atr);
        }
    };

    let ctx = unsafe { &mut CTX };

    let context = &mut ctx[slot as usize];

    match action {
        IFD_POWER_DOWN => {
            if vicc_power_off(context) < 0 {

                // handle error
                if result != IFD_SUCCESS as DWORD && unsafe { *atr_length } != 0 {
                    unsafe { *atr_length = 0 };
                    return result;
                } else {
                    result = IFDHGetCapabilities(lun, TAG_IFD_ATR, atr_length, atr);
                }
            } else {
                result = IFD_SUCCESS as u64;
            }
        }
        IFD_POWER_UP => {
            if vicc_power_on(context) < 0 {

                // handle error
                if result != IFD_SUCCESS as DWORD && unsafe { *atr_length } != 0 {
                    unsafe { *atr_length = 0 };
                    return result;
                } else {
                    result = IFDHGetCapabilities(lun, TAG_IFD_ATR, atr_length, atr);
                }
            } else {
                result = IFD_SUCCESS as u64;
            }
        }
        IFD_RESET => {
            if vicc_reset(context) < 0 {

                // handle error
                if result != IFD_SUCCESS as DWORD && unsafe { *atr_length } != 0 {
                    unsafe { *atr_length = 0 };
                    return result;
                } else {
                    result = IFDHGetCapabilities(lun, TAG_IFD_ATR, atr_length, atr);
                }
            } else {
                result = IFD_SUCCESS as u64;
            }
        }
        _ => {
            result = IFD_NOT_SUPPORTED as DWORD;
        }
    }

    result
}

#[no_mangle]
pub extern "C" fn IFDHTransmitToICC(
    lun: DWORD,
    send_pci: ScardIoHeader,
    tx_buffer: PUCHAR,
    tx_length: DWORD,
    mut rx_buffer: PUCHAR,
    mut rx_length: DWORD,
    recv_pci: PscardIoHeader,
) -> DWORD {
    let slot: libc::c_ulong = lun & 0xffff;

    let mut result = IFD_COMMUNICATION_ERROR as DWORD;

    let mut rapdu: *mut libc::c_uchar = std::ptr::null_mut();

    let mut size: libc::ssize_t;

    let ctx = unsafe { &mut CTX };

    let context = &mut ctx[slot as usize];

    if slot > VICC_MAX_SLOTS as u64 {
        //handle error
        if result != IFD_SUCCESS as DWORD && rx_length != 0 {
            rx_length = 0;
        }
        unsafe { free(rapdu as *mut libc::c_void) };
        return result;
    };

    if rx_length == 0 || recv_pci.is_null() {
        if result != IFD_SUCCESS as DWORD && rx_length != 0 {
            rx_length = 0;
        }
        unsafe { free(rapdu as *mut libc::c_void) };
        return result;
    }

    // let rapdu_buffer = unsafe { slice::from_raw_parts_mut(rapdu as *mut u8, 1) };
    //let mut rapdu_buffer = vec![];

    size = if let Some(value) = context {
        vicc_transmit(
            value,
            tx_length as libc::size_t,
            tx_buffer,
            &mut rapdu,
        )
    } else {
        -1
    };

    if size < 0 {
        if result != IFD_SUCCESS as DWORD && rx_length != 0 {
            rx_length = 0;
        }
        unsafe { free(rapdu as *mut libc::c_void) };
        return result;
    }

    rx_length = size as u64;
    (unsafe { *recv_pci }).protocol = 1;
    //let value = rapdu_buffer[..].as_ptr() as PUCHAR;
    //rx_buffer = value;
    unsafe { memcpy(rx_buffer as *mut libc::c_void, rapdu as *mut libc::c_void, size as usize);}

    result
}

#[no_mangle]
pub extern "C" fn IFDHICCPresence(lun: DWORD) -> DWORD {
    let slot: libc::c_ulong = lun & 0xffff;

    if slot > VICC_MAX_SLOTS as u64 {
        return IFD_COMMUNICATION_ERROR as DWORD;
    }
    match &mut unsafe { &mut CTX }[slot as usize] {
        Some(ctx) => /*match vicc_present(ctx) {
            0 => {
                println!("NOT PRESENT");
                IFD_ICC_NOT_PRESENT as DWORD
            }
            1 => {
                println!("PRESENT");
                IFD_ICC_PRESENT as DWORD
            }
            _ => IFD_COMMUNICATION_ERROR as DWORD,

        },*/
        {
            let presence = vicc_present(ctx);

        
            if presence == 0 {
                print!("NOT PRESENT \n");
                return IFD_ICC_NOT_PRESENT as u64
            }

            if presence == 1 {
                println!("PRESENT \n ");
                return IFD_ICC_PRESENT as u64
            }

            return IFD_COMMUNICATION_ERROR as u64
        }
        None => IFD_COMMUNICATION_ERROR as DWORD,
    }
}

#[no_mangle]
pub extern "C" fn IFDHCreateChannelByName(lun: DWORD, device_name: LPSTR) -> DWORD {

    //let stuff = unsafe { CString::from_raw(device_name) }; // "/dev/null:0x8C7B"

    let result = IFDHCreateChannel(lun, 35963);

    result
}
