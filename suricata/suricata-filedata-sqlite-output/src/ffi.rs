// Copyright (C) 2025  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use std::os::raw::{c_char, c_int, c_uint, c_void};

// Rust representation of suricata/src/util-file.h `File` struct
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct File {
    flags: u16,
    name_len: u16,
    state: c_int,
    sb: *mut c_void,
    file_track_id: u32,
    pub file_store_id: u32,
    fd: c_int,
    name: *mut u8,
    magic: *mut c_char,
    next: *mut File,
    md5_ctx: *mut c_void,
    md5: [u8; 16],
    sha1_ctx: *mut c_void,
    sha1: [u8; 20],
    sha256_ctx: *mut c_void,
    pub sha256: [u8; 32],
    content_inspected: u64,
    content_stored: u64,
    size: u64,
    inspect_window: u32,
    inspect_min_size: u32,
    start: u64,
    end: u64,
    sid: *mut u32,
    sid_cnt: u32,
    sid_max: u32,
}

pub type LoggerId = c_uint;
pub const LOGGER_USER: LoggerId = 26;
pub const OUTPUT_FILEDATA_FLAG_CLOSE: u8 = 0x02;
pub type SCFiledataLogger = extern "C" fn(
    *mut *mut c_void, // ThreadVars *
    thread_data: *mut *mut c_void,
    p: *const *mut c_void, // Packet *
    ff: *mut File,
    tx: *mut *mut c_void,
    tx_id: u64,
    data: *const u8,
    data_len: u32,
    flags: u8,
    dir: u8,
) -> c_int;

extern "C" {
    pub fn FileForceFilestoreEnable();
    pub fn FileForceSha256Enable();
    pub fn ProvidesFeature(feature_name: *const c_char);
    pub fn SCOutputRegisterFiledataLogger(
        logger_id: LoggerId,
        name: *const c_char,
        LogFunc: SCFiledataLogger,
        initdata: *mut c_void,
        ThreadInit: extern "C" fn(*mut *mut c_void, *const *mut c_void, *mut *mut c_void) -> c_int,
        ThreadDeinit: extern "C" fn(*mut *mut c_void, *mut *mut c_void),
    ) -> c_int;
}
