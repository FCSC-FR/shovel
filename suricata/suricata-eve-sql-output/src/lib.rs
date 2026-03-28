// Copyright (C) 2024  ANSSI
// Copyright (C) 2025  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

mod database;
mod ffi;

use std::fmt::Debug;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::mpsc;
use suricata_sys::sys::{SC_API_VERSION, SC_PACKAGE_VERSION, SCPlugin};

// Default configuration values.
const DEFAULT_DATABASE_URL: &str = "sqlite://./suricata/output/eve.db?mode=rwc";
const DEFAULT_BUFFER_SIZE: usize = 1000;

#[derive(Debug, Clone)]
struct Config {
    database_url: String,
    buffer: usize,
}

impl Config {
    fn new() -> Self {
        Self {
            database_url: std::env::var("EVE_DATABASE_URL")
                .unwrap_or_else(|_| DEFAULT_DATABASE_URL.into()),
            buffer: std::env::var("EVE_BUFFER")
                .unwrap_or_else(|_| DEFAULT_BUFFER_SIZE.to_string())
                .parse()
                .unwrap_or(DEFAULT_BUFFER_SIZE),
        }
    }
}

struct Context {
    tx: mpsc::SyncSender<String>,
    count: usize,
}

extern "C" fn output_init(_conf: *const c_void, threaded: bool, data: *mut *mut c_void) -> c_int {
    assert!(
        !threaded,
        "SQL output plugin does not support threaded EVE yet"
    );

    // Load configuration
    let config = Config::new();

    let (tx, rx) = mpsc::sync_channel(config.buffer);
    let mut database_client = database::Database::new(config.database_url, rx);
    std::thread::spawn(move || database_client.run());
    let context_ptr = Box::into_raw(Box::new(Context { tx, count: 0 }));

    unsafe {
        *data = context_ptr.cast();
    }
    0
}

extern "C" fn output_deinit(data: *const c_void) {
    let context = unsafe { Box::from_raw(data as *mut Context) };
    log::info!("SQL Eve output finished: count={}", context.count);
    std::mem::drop(context);
}

extern "C" fn output_write(
    buffer: *const c_char,
    buffer_len: c_int,
    data: *const c_void,
    _thread_data: *const c_void,
) -> c_int {
    // Handle FFI arguments
    let context = unsafe { &mut *(data as *mut Context) };
    let text = unsafe {
        str::from_utf8_unchecked(
            std::ffi::CStr::from_bytes_with_nul_unchecked(std::slice::from_raw_parts(
                buffer.cast(),
                buffer_len.unsigned_abs().saturating_add(1) as usize,
            ))
            .to_bytes(),
        )
    };

    // Send text buffer to database thread
    context.count = context.count.saturating_add(1);
    if let Err(_err) = context.tx.send(text.to_owned()) {
        log::error!("Failed to send Eve record to database thread");
        return -1;
    }
    0
}

const extern "C" fn output_thread_init(
    _data: *const c_void,
    _thread_id: std::os::raw::c_int,
    _thread_data: *mut *mut c_void,
) -> c_int {
    0
}

const extern "C" fn output_thread_deinit(_data: *const c_void, _thread_data: *mut c_void) {}

extern "C" fn plugin_init() {
    // Init Rust logger
    // don't log using `suricata` crate to reduce build time.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Register new eve filetype, then we can use it with `eve-log.filetype=sql`
    let file_type = ffi::SCEveFileType {
        name: c"sql".as_ptr(),
        Init: output_init,
        ThreadInit: output_thread_init,
        Write: output_write,
        ThreadDeinit: output_thread_deinit,
        Deinit: output_deinit,
        pad: [0, 0],
    };
    let file_type_ptr = Box::into_raw(Box::new(file_type));
    if !unsafe { ffi::SCRegisterEveFileType(file_type_ptr) } {
        log::error!("Failed to register SQL Eve plugin");
    }
}

/// Plugin entrypoint, registers [`plugin_init`] function in Suricata
#[unsafe(no_mangle)]
extern "C" fn SCPluginRegister() -> *const SCPlugin {
    let plugin = SCPlugin {
        version: SC_API_VERSION,
        suricata_version: SC_PACKAGE_VERSION.as_ptr().cast::<::std::os::raw::c_char>(),
        name: c"Eve SQL Output".as_ptr(),
        plugin_version: c"0.1.0".as_ptr(),
        license: c"GPL-2.0".as_ptr(),
        author: c"ECSC TeamFrance".as_ptr(),
        Init: Some(plugin_init),
    };
    Box::into_raw(Box::new(plugin))
}
