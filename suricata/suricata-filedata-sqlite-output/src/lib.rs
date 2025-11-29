// Copyright (C) 2025  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

mod database;
mod ffi;

use std::collections::HashMap;
use std::fmt::Debug;
use std::os::raw::{c_int, c_void};
use std::sync::mpsc;
use suricata_sys::sys::{SCPlugin, SC_API_VERSION, SC_PACKAGE_VERSION};

// Default configuration values.
const DEFAULT_DATABASE_URI: &str = "file:suricata/output/filedata.sqlar";
const DEFAULT_BUFFER_SIZE: &str = "1000";

#[derive(Debug, Clone)]
struct Config {
    filename: String,
    buffer: usize,
}

impl Config {
    fn new() -> Self {
        Self {
            filename: std::env::var("FILEDATA_FILENAME").unwrap_or(DEFAULT_DATABASE_URI.into()),
            buffer: std::env::var("FILEDATA_BUFFER")
                .unwrap_or(DEFAULT_BUFFER_SIZE.into())
                .parse()
                .expect("FILEDATA_BUFFER is not an integer"),
        }
    }
}

struct Filedata {
    blob: Vec<u8>,
    sha256: [u8; 32],
}

struct Context {
    tx: mpsc::SyncSender<Filedata>,
    count: usize,
    filedata_blob: HashMap<u32, Vec<u8>>,
}

extern "C" fn filedata_log(
    _thread_vars: *mut *mut c_void, // ThreadVars *
    thread_data: *mut *mut c_void,
    _p: *const *mut c_void, // Packet *
    ff: *mut ffi::File,
    _tx: *mut *mut c_void,
    _tx_id: u64,
    data: *const u8,
    data_len: u32,
    flags: u8,
    _dir: u8,
) -> c_int {
    // Handle FFI arguments
    let context = unsafe { &mut *thread_data.cast::<Context>() };
    let ff = unsafe { &mut *(ff) };
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len as usize) };

    // Write data blob to temporary buffer
    match context.filedata_blob.get_mut(&ff.file_store_id) {
        Some(pending_blob) => {
            pending_blob.append(data_slice.to_owned().as_mut());
        }
        None => {
            context
                .filedata_blob
                .insert(ff.file_store_id, data_slice.to_owned());
        }
    }

    if flags & ffi::OUTPUT_FILEDATA_FLAG_CLOSE != 0 {
        // Got last part of data, send filedata to database thread
        context.count += 1;
        let blob = context.filedata_blob.remove(&ff.file_store_id).unwrap();
        let sha256 = ff.sha256.to_owned();
        let filedata = Filedata { blob, sha256 };
        if let Err(_err) = context.tx.send(filedata) {
            log::error!("Failed to send filedata to database thread");
            return -1;
        }
    }
    0
}

extern "C" fn filedata_thread_init(
    _thread_vars: *mut *mut c_void, // ThreadVars *
    _initdata: *const *mut c_void,
    thread_data: *mut *mut c_void,
) -> c_int {
    // Load configuration
    let config = Config::new();

    // Create thread context
    let (tx, rx) = mpsc::sync_channel(config.buffer);
    let mut database_client = match database::Database::new(config.filename, rx) {
        Ok(client) => client,
        Err(err) => {
            log::error!("Failed to initialize database client: {err:?}");
            panic!()
        }
    };
    std::thread::spawn(move || database_client.run());
    let context_ptr = Box::into_raw(Box::new(Context {
        tx,
        count: 0,
        filedata_blob: HashMap::new(),
    }));

    unsafe {
        *thread_data = context_ptr.cast();
    }
    0
}

extern "C" fn filedata_thread_deinit(
    _thread_vars: *mut *mut c_void,
    thread_data: *mut *mut c_void,
) {
    let context = unsafe { Box::from_raw(thread_data.cast::<Context>()) };
    log::info!("SQLite output finished: count={}", context.count);
    std::mem::drop(context);
}

extern "C" fn plugin_init() {
    // Init Rust logger
    // don't log using `suricata` crate to reduce build time.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Force filestore in engine
    unsafe {
        ffi::FileForceFilestoreEnable();
        ffi::FileForceSha256Enable();
        ffi::ProvidesFeature(c"output::file-store".as_ptr());
    }

    // Register new filedata logger
    if !unsafe {
        ffi::SCOutputRegisterFiledataLogger(
            ffi::LOGGER_USER,
            c"filedata-sqlite".as_ptr(),
            filedata_log,
            std::ptr::null_mut(),
            filedata_thread_init,
            filedata_thread_deinit,
        )
    } == 0
    {
        log::error!("Failed to register sqlite plugin");
    }
}

/// Plugin entrypoint, registers [`plugin_init`] function in Suricata
#[no_mangle]
extern "C" fn SCPluginRegister() -> *const SCPlugin {
    let plugin = SCPlugin {
        version: SC_API_VERSION,
        suricata_version: SC_PACKAGE_VERSION.as_ptr() as *const i8,
        name: c"Filedata SQLite Output".as_ptr(),
        plugin_version: c"0.1.0".as_ptr(),
        license: c"GPL-2.0".as_ptr(),
        author: c"ECSC TeamFrance".as_ptr(),
        Init: Some(plugin_init),
    };
    Box::into_raw(Box::new(plugin))
}
