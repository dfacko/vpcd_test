pub const INVALID_SOCKET: libc::c_int = -1;
pub const VPCD_CTRL_ATR: libc::c_uchar = 4;
pub const VPCD_CTRL_LEN: libc::c_uchar = 1;

pub const VPCD_CTRL_OFF: libc::c_int = 0;
pub const VPCD_CTRL_ON: libc::c_int = 1;
pub const VPCD_CTRL_RESET: libc::c_int = 2;

use std::{
    cell::{Ref, RefCell, RefMut},
    io::Write,
    net::{SocketAddr, TcpStream},
    ops::Not,
    slice,
};

use crate::{
    lock::{create_lock, free_lock, lock, unlock},
    wintypes::DWORD,
};

#[repr(C)]
#[derive(Debug)]
pub struct ViccCtx {
    pub server_sock: Option<Socket>,
    pub client_sock: libc::c_int,
    pub hostname: *mut libc::c_char,
    pub port: libc::c_ushort,
    pub io_lock: *mut libc::c_void,
}

#[repr(C)]
#[derive(Debug)]
pub struct PcscTlvStructure {
    pub tag: u8,    //libc::uint8_t,
    pub lenght: u8, //libc::uint8_t,
    pub value: u32, //*mut libc::uint32_t,
}

impl Default for ViccCtx {
    fn default() -> Self {
        Self {
            server_sock: None,
            client_sock: INVALID_SOCKET,
            hostname: std::ptr::null_mut(),
            port: 0,
            io_lock: std::ptr::null_mut(),
        }
    }
}

pub fn vicc_init(hostname: *const libc::c_char, port: libc::c_ushort) -> RefCell<ViccCtx> {
    let mut ctx_cell: RefCell<ViccCtx> = RefCell::new(Default::default());

    let mut ctx = ctx_cell.get_mut();

    ctx.io_lock = std::ptr::null_mut();
    ctx.server_sock = None;
    ctx.client_sock = INVALID_SOCKET;
    ctx.port = port;
    ctx.io_lock = create_lock();

    // TODO: check if io_lock is set

    if !hostname.is_null() {
        //TODO create client socket
    } else {
        ctx.server_sock = opensock(port);
    }

    ctx_cell
}

use libc::{
    accept, bind, close, listen, poll, pollfd, recv, send, sockaddr, sockaddr_in, socklen_t,
    INADDR_ANY, MSG_NOSIGNAL, MSG_WAITALL, PF_INET, POLLIN,
};
use socket::{htonl, htons, ntohs, Socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR};

fn opensock(port: libc::c_ushort) -> Option<Socket> {
    let yes: socklen_t = 1;
    let mut server_socket_address: sockaddr_in = unsafe { std::mem::zeroed() };

    let socket = match Socket::new(AF_INET, SOCK_STREAM, 0) {
        Ok(socket) => socket,
        Err(e) => {
            return None;
        }
    };

    match socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, yes) {
        Ok(_) => (),
        Err(e) => {
            socket.close().unwrap();
            return None;
        }
    };

    server_socket_address.sin_family = PF_INET as u16;
    server_socket_address.sin_port = htons(port);
    server_socket_address.sin_addr.s_addr = htonl(INADDR_ANY);

    let addr_ptr = &server_socket_address as *const sockaddr_in as *const sockaddr;

    let ret = unsafe {
        bind(
            socket.fileno(),
            addr_ptr,
            std::mem::size_of::<sockaddr_in>() as u32,
        )
    };

    if ret != 0 {
        socket.close();
        return None;
    }

    let listen = unsafe { listen(socket.fileno(), 0) };

    if listen != 0 {
        socket.close();
        return None;
    }

    Some(socket)
}

pub fn vicc_exit_2(context: &mut Option<RefCell<ViccCtx>>) -> libc::c_int {
    let mut result = 0;
    match context {
        Some(ctx) => {
            let mut ctx = ctx.borrow_mut();
            free_lock(ctx.io_lock);
            if ctx.client_sock != INVALID_SOCKET {
                let close_result = unsafe { close(ctx.client_sock) };
                if close_result < 0 {
                    result -= 1;
                }
                ctx.client_sock = INVALID_SOCKET;
            }

            if ctx.server_sock.is_some() {
                let server_sock_close_result =
                    unsafe { close(ctx.server_sock.as_ref().unwrap().fileno()) };
                if server_sock_close_result == INVALID_SOCKET {
                    result -= 1;
                }
            }

            result
        }
        None => 0 as libc::c_int,
    }
}

pub fn vicc_exit(context: &mut Option<RefCell<ViccCtx>>) -> libc::c_int {
    let mut result = 0;
    match context {
        Some(ctx) => {
            result = vicc_eject(ctx);
            let ctx = ctx.borrow_mut();
            free_lock(ctx.io_lock);

            if ctx.server_sock.is_some() {
                let server_sock_close_result =
                    unsafe { close(ctx.server_sock.as_ref().unwrap().fileno()) };
                if server_sock_close_result == INVALID_SOCKET {
                    result -= 1;
                }
            }

            result
        }
        None => 0 as libc::c_int,
    }
}

pub fn vicc_eject(context: &mut RefCell<ViccCtx>) -> libc::c_int {
    let mut result = 0;
    let mut context = context.borrow_mut();
    if context.client_sock != INVALID_SOCKET {
        let client_sock_close = unsafe { close(context.client_sock) };
        if client_sock_close < 0 {
            result -= 1;
        }
        context.client_sock = INVALID_SOCKET;
    }

    result
}

pub fn vicc_getatr(
    mut context: &mut RefCell<ViccCtx>,
    atr: *mut *mut libc::c_uchar,
) -> libc::ssize_t {
    let mut i: libc::c_uchar = VPCD_CTRL_LEN;

    let transmit_result: libc::ssize_t = vicc_transmit(
        context,
        VPCD_CTRL_LEN.into(),
        &mut i as *mut libc::c_uchar,
        atr,
    );

    transmit_result
}

pub fn vicc_transmit(
    context: &mut RefCell<ViccCtx>,
    apdu_len: libc::size_t,
    apdu: *mut libc::c_uchar,
    rapdu: *mut *mut libc::c_uchar,
) -> libc::ssize_t {
    let mut result: libc::ssize_t = -1;

    if lock(context.borrow().io_lock) == 1 {
        if apdu_len != 0
        /*&& apdu != &mut 0_u8*/
        {
            result = send_to_vicc(context, apdu_len, apdu);
        } else {
            result = 1;
        }

        if result > 0 && !rapdu.is_null()
        //DEBUG HERE
        /*&& rapdu != &mut 0 as &mut libc::ssize_t*/
        {
            result = recv_from_vicc(context, rapdu);
            unlock(context.borrow().io_lock);
        }
    }

    if result <= 0 {
        vicc_eject(context);
    }

    result
}

pub fn send_to_vicc(
    mut context: &mut RefCell<ViccCtx>,
    length: libc::size_t,
    buffer: *mut libc::c_uchar,
) -> libc::ssize_t {
    let mut result: libc::ssize_t = 0;
    let mut size: u16 = 0;

    if length > 0xFFF {
        return result;
    };

    size = htons(length as u16);

    result = sendall(
        context.borrow().client_sock,
        (&mut size as *mut u16) as *mut libc::c_void,
        std::mem::size_of_val(&size),
    );

    if result == std::mem::size_of_val(&size) as libc::ssize_t {
        result = sendall(
            context.borrow().client_sock,
            buffer as *mut libc::c_void,
            length,
        );
    }

    if result < 0 {
        vicc_eject(context);
    }

    result
}

pub fn sendall(socket: i32, buffer: *mut libc::c_void, size: libc::size_t) -> libc::ssize_t {
    let mut sent: libc::size_t = 0;
    let mut r: libc::ssize_t = 0;

    while sent < size {
        let r = unsafe {
            libc::send(
                socket,
                buffer as *const libc::c_void,
                size - sent,
                libc::MSG_NOSIGNAL,
            )
        };

        if r < 0 {
            return r;
        }
        sent += r as usize;
    }

    sent as libc::ssize_t
}

pub fn recv_from_vicc(
    mut context: &mut RefCell<ViccCtx>,
    buffer: *mut *mut libc::c_uchar,
) -> libc::ssize_t {
    let mut result: libc::ssize_t = 0;
    let mut size: u16 = 0;

    result = recvall(
        context.borrow().client_sock,
        &mut size as *mut _ as *mut libc::c_void,
        std::mem::size_of_val(&size),
    );

    //panic!();

    if result < size as isize {
        return result;
    }

    size = ntohs(size);

    /*if (0 != size)
    {
        p = realloc(*buffer, size);
        if (p == NULL)
        {
            errno = ENOMEM;
            return -1;
        }
        *buffer = p;
    } */

    let result = recvall(
        context.borrow().client_sock,
        unsafe { *buffer as *mut libc::c_void },
        size as usize,
    );

    panic!();

    result
}

pub fn recvall(socket: i32, buffer: *mut libc::c_void, size: libc::size_t) -> libc::ssize_t {
    let mut total_received = 0;
    let result = unsafe { recv(socket, buffer, size, MSG_WAITALL | MSG_NOSIGNAL) };

    result
}

pub fn vicc_present(context: &mut RefCell<ViccCtx>) -> DWORD {
    //let atr: *mut libc::c_char = std::ptr::null_mut();

    //let mut atr = vec![]; Change this to unsinged char i guess

    let mut atr: *mut libc::c_uchar = std::ptr::null_mut();

    //let mut atr_ptr: *mut *mut libc::c_uchar = &mut atr;

    let connect_result = vicc_connect(context, 0, 0);
    let getatr_result = vicc_getatr(context, &mut atr);

    if connect_result != 0 {
        //panic!("custom panic connect result is not 0");
    }

    if connect_result == 0 || getatr_result <= 0 {
        return 0;
    }

    1
}

pub fn vicc_connect(context: &mut RefCell<ViccCtx>, secs: i32, usecs: i32) -> i32 {
    let mut context = context.borrow_mut();

    if context.client_sock == INVALID_SOCKET {
        if context.hostname.is_null() {
            // server mode, try accept client
            let server_socket = &context.server_sock;
            context.client_sock = wait_for_client(&server_socket, secs, usecs);
        } else {
            panic!();
            //ctx.clientsock = contectsock();
            return 0;
        }
    };

    if context.client_sock == INVALID_SOCKET {
        0
    } else {
        1
    }
}

pub fn wait_for_client(socket: &Option<Socket>, secs: i32, usecs: i32) -> i32 {
    let mut client_socket_address: sockaddr_in = unsafe { std::mem::zeroed() };
    let mut client_socket_len: socklen_t =
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let timeout: i32;
    let mut pfd: pollfd = pollfd {
        fd: socket.as_ref().unwrap().fileno(),
        events: POLLIN,
        revents: 0,
    };

    timeout = secs * 1000 + usecs / 1000;

    if unsafe { poll(&mut pfd, 1, timeout) } == -1 {
        return INVALID_SOCKET;
    };

    if pfd.revents & POLLIN != 0 {
        let result = unsafe {
            accept(
                socket.as_ref().unwrap().fileno(),
                &mut client_socket_address as *mut _ as *mut sockaddr,
                &mut client_socket_len,
            )
        };

        return result;
    }

    return INVALID_SOCKET;
}

pub fn vicc_power_on(context: &mut Option<RefCell<ViccCtx>>) -> i32 {
    let mut i: libc::c_uchar = VPCD_CTRL_ON as libc::c_uchar;
    let ptr = &mut i;
    let mut result = 0;
    let buffer = unsafe { slice::from_raw_parts_mut(ptr as *mut u8, 1) };

    if let Some(value) = context {
        if lock(value.borrow().io_lock) == 0 {
            result = send_to_vicc(value, VPCD_CTRL_LEN as libc::size_t, ptr) as i32;
            unlock(value.borrow().io_lock);
        }
    }

    result
}

pub fn vicc_power_off(context: &mut Option<RefCell<ViccCtx>>) -> i32 {
    let mut i: libc::c_uchar = VPCD_CTRL_OFF as libc::c_uchar;
    let ptr = &mut i;
    let mut result = 0;
    let buffer = unsafe { slice::from_raw_parts_mut(ptr as *mut u8, 1) };

    if let Some(value) = context {
        if lock(value.borrow().io_lock) == 0 {
            result = send_to_vicc(value, VPCD_CTRL_LEN as libc::size_t, ptr) as i32;
            unlock(value.borrow().io_lock);
        }
    }

    result
}

pub fn vicc_reset(context: &mut Option<RefCell<ViccCtx>>) -> i32 {
    let mut i: libc::c_uchar = VPCD_CTRL_RESET as libc::c_uchar;
    let ptr = &mut i;
    let mut result = 0;
    let buffer = unsafe { slice::from_raw_parts_mut(ptr as *mut u8, 1) };

    if let Some(value) = context {
        if lock(value.borrow().io_lock) == 0 {
            result = send_to_vicc(value, VPCD_CTRL_LEN as libc::size_t, ptr) as i32;
            unlock(value.borrow().io_lock);
        }
    }

    result
}
