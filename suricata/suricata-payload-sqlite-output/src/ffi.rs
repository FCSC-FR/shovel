// Copyright (C) 2026  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use std::os::raw::{c_char, c_int, c_uint, c_void};

pub type LoggerId = c_uint;
pub const LOGGER_USER: LoggerId = 26;

// Packet flags
pub const PKT_NOPACKET_INSPECTION: u32 = 1 << 0;
pub const PKT_STREAM_NOPCAPLOG: u32 = 1 << 12;

// HACK: use pahole to find offset
// Replace this with Suricata 9 ffi
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Flow_ {
    _gap0: [u8; 72],
    pub flow_hash: u32,
    _gap1: [u8; 164],
    pub startts: u64,
}
pub type Flow = Flow_;

// HACK: use pahole to find offset
// Replace this with Suricata 9 ffi
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Packet_ {
    _gap0: [u8; 60],
    pub flags: u32,
    pub flow: *const Flow,
    _gap1: [u8; 200],
    pub payload: *const u8,
    pub payload_len: u16,
}
pub type Packet = Packet_;

pub type PacketLogger = extern "C" fn(
    *mut *mut c_void, // ThreadVars *
    thread_data: *mut *mut c_void,
    p: *const Packet,
) -> c_int;

pub type PacketLogCondition = extern "C" fn(
    *mut *mut c_void, // ThreadVars *
    thread_data: *mut *mut c_void,
    p: *const Packet,
) -> bool;

unsafe extern "C" {
    pub fn SCOutputRegisterPacketLogger(
        logger_id: LoggerId,
        name: *const c_char,
        LogFunc: PacketLogger,
        ConditionFunc: PacketLogCondition,
        initdata: *mut c_void,
        ThreadInit: extern "C" fn(*mut *mut c_void, *const *mut c_void, *mut *mut c_void) -> c_int,
        ThreadDeinit: extern "C" fn(*mut *mut c_void, *mut *mut c_void),
    ) -> c_int;

    pub fn FlowGetPacketDirection(f: *const Flow, p: *const Packet) -> c_int;
}

/// Equivalent of Suricata FlowGetId
pub fn flow_get_id(f: &Flow) -> i64 {
    let secs = f.startts & 0x0FFF_FFFF_FFFF;
    let usecs = (f.startts >> 44) & 0xFFFFF;
    let id =
        (((secs & 0xFFFF) << 48) | ((usecs & 0xFFFF) << 32) | u64::from(f.flow_hash)).cast_signed();
    id & 0x0007_FFFF_FFFF_FFFF
}
