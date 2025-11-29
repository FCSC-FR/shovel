// Copyright (C) 2024  ANSSI
// Copyright (C) 2025  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use std::os::raw::{c_char, c_int, c_void};

/// Rust representation of a Eve FileType
#[repr(C)]
#[allow(non_snake_case)]
pub struct SCEveFileType {
    pub name: *const c_char,
    pub Init: extern "C" fn(*const c_void, bool, *mut *mut c_void) -> c_int,
    pub ThreadInit: extern "C" fn(*const c_void, std::os::raw::c_int, *mut *mut c_void) -> c_int,
    pub Write: extern "C" fn(*const c_char, c_int, *const c_void, *const c_void) -> c_int,
    pub ThreadDeinit: extern "C" fn(*const c_void, thread_data: *mut c_void),
    pub Deinit: extern "C" fn(*const c_void),
    pub pad: [usize; 2], // Suricata internal list management pointers.
}

extern "C" {
    pub fn SCRegisterEveFileType(filetype: *const SCEveFileType) -> bool;
}
