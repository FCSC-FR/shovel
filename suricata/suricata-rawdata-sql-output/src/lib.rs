// Copyright (C) 2026  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

mod database;
mod ffi;

use std::collections::HashMap;
use std::fmt::Debug;
use std::os::raw::{c_int, c_void};
use std::sync::mpsc;
use suricata_sys::sys::{SC_API_VERSION, SC_PACKAGE_VERSION, SCPlugin};

// Default configuration values.
const DEFAULT_DATABASE_URL: &str = "sqlite://./suricata/output/payload.db?mode=rwc";
const DEFAULT_BUFFER_SIZE: usize = 1000;

#[derive(Debug, Clone)]
struct Config {
    database_url: String,
    buffer: usize,
}

impl Config {
    fn new() -> Self {
        Self {
            database_url: std::env::var("RAWDATA_DATABASE_URL")
                .unwrap_or_else(|_| DEFAULT_DATABASE_URL.into()),
            buffer: std::env::var("RAWDATA_BUFFER")
                .unwrap_or_else(|_| DEFAULT_BUFFER_SIZE.to_string())
                .parse()
                .unwrap_or(DEFAULT_BUFFER_SIZE),
        }
    }
}

struct Rawdata {
    data: Vec<u8>,
    flow_id: i64,
    packet_count: i64,
    direction: i32,
}

struct Context {
    tx: mpsc::SyncSender<Rawdata>,
    count: usize,
    flow_packet_count: HashMap<i64, i64>,
}

extern "C" fn packet_log(
    _thread_vars: *mut *mut c_void, // ThreadVars *
    thread_data: *mut *mut c_void,
    pkt: *const ffi::Packet,
) -> c_int {
    // Handle FFI arguments
    let pkt = unsafe { &*pkt };
    let data = unsafe { std::slice::from_raw_parts(pkt.payload, pkt.payload_len as usize) };
    let flow = unsafe { &*pkt.flow };
    let flow_id = ffi::flow_get_id(flow);
    let direction = unsafe { ffi::FlowGetPacketDirection(flow, pkt) };

    // Get payload count for this flow
    let context = unsafe { &mut *thread_data.cast::<Context>() };
    context.count = context.count.saturating_add(1);
    let packet_count = *context.flow_packet_count.get(&flow_id).unwrap_or(&0);
    context
        .flow_packet_count
        .insert(flow_id, packet_count.saturating_add(1));

    let rawdata = Rawdata {
        data: data.to_vec(),
        flow_id,
        packet_count,
        direction,
    };
    if let Err(_err) = context.tx.send(rawdata) {
        log::error!("Failed to send rawdata to database thread");
        return -1;
    }
    0
}

const extern "C" fn packet_log_condition(
    _thread_vars: *mut *mut c_void, // ThreadVars *
    _thread_data: *mut *mut c_void,
    pkt: *const ffi::Packet,
) -> bool {
    let pkt = unsafe { &*pkt };
    pkt.payload_len != 0
        && (pkt.flags & (ffi::PKT_NOPACKET_INSPECTION | ffi::PKT_STREAM_NOPCAPLOG) == 0)
}

extern "C" fn packet_thread_init(
    _thread_vars: *mut *mut c_void, // ThreadVars *
    _initdata: *const *mut c_void,
    thread_data: *mut *mut c_void,
) -> c_int {
    // Load configuration
    let config = Config::new();

    // Create thread context
    let (tx, rx) = mpsc::sync_channel(config.buffer);
    let mut database_client = database::Database::new(config.database_url, rx);
    std::thread::spawn(move || database_client.run());
    let context_ptr = Box::into_raw(Box::new(Context {
        tx,
        count: 0,
        flow_packet_count: HashMap::new(),
    }));

    unsafe {
        *thread_data = context_ptr.cast();
    }
    0
}

extern "C" fn packet_thread_deinit(_thread_vars: *mut *mut c_void, thread_data: *mut *mut c_void) {
    let context = unsafe { Box::from_raw(thread_data.cast::<Context>()) };
    log::info!("SQL rawdata output finished: count={}", context.count);
    std::mem::drop(context);
}

extern "C" fn plugin_init() {
    // Init Rust logger
    // don't log using `suricata` crate to reduce build time.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Register new packets logger
    if !unsafe {
        ffi::SCOutputRegisterPacketLogger(
            ffi::LOGGER_USER,
            c"rawdata-sql".as_ptr(),
            packet_log,
            packet_log_condition,
            std::ptr::null_mut(),
            packet_thread_init,
            packet_thread_deinit,
        )
    } == 0
    {
        log::error!("Failed to register packets logger in rawdata SQL plugin");
    }
}

/// Plugin entrypoint, registers [`plugin_init`] function in Suricata
#[unsafe(no_mangle)]
extern "C" fn SCPluginRegister() -> *const SCPlugin {
    let plugin = SCPlugin {
        version: SC_API_VERSION,
        suricata_version: SC_PACKAGE_VERSION.as_ptr().cast::<::std::os::raw::c_char>(),
        name: c"Rawdata SQL Output".as_ptr(),
        plugin_version: c"0.1.0".as_ptr(),
        license: c"GPL-2.0".as_ptr(),
        author: c"ECSC TeamFrance".as_ptr(),
        Init: Some(plugin_init),
    };
    Box::into_raw(Box::new(plugin))
}
