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
const DEFAULT_DATABASE_URL: &str = "sqlite://./output_suricata/eve.db?mode=rwc";
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

struct EveEvent {
    type_: String,
    data: String,
}

struct Context {
    tx: mpsc::SyncSender<EveEvent>,
}

extern "C" fn output_init(_conf: *const c_void, threaded: bool, _data: *mut *mut c_void) -> c_int {
    assert!(
        !threaded,
        "SQL output plugin does not support threaded EVE yet"
    );
    0
}

const extern "C" fn output_deinit(_data: *const c_void) {}

extern "C" fn output_write(
    buffer: *const c_char,
    buffer_len: c_int,
    _init_data: *const c_void,
    thread_data: *mut c_void,
) -> c_int {
    // Handle FFI arguments
    let context =
        unsafe { thread_data.cast::<Context>().as_ref() }.expect("null thread_data pointer");
    let text = unsafe {
        str::from_utf8_unchecked(
            std::ffi::CStr::from_bytes_with_nul_unchecked(std::slice::from_raw_parts(
                buffer.cast(),
                buffer_len.unsigned_abs().saturating_add(1) as usize,
            ))
            .to_bytes(),
        )
    };

    // Zero-copy extraction of the event_type
    let event_type = match text.split_once(r#","event_type":""#) {
        Some((_, p)) => p,
        None => text
            .split(r#", "event_type": ""#)
            .nth(1)
            .unwrap_or_default(),
    }
    .split('"')
    .next()
    .unwrap_or("unknown");

    // Send event to database thread
    let event = EveEvent {
        type_: event_type.to_owned(),
        data: escape_unicode_null(text).to_owned(),
    };
    if let Err(err) = context.tx.send(event) {
        panic!("Database thread is no longer alive: {err:?}");
    }
    0
}

/// PostgreSQL TEXT cannot contain NULL bytes: `\u0000 cannot be converted to text`.
/// This means that PostgreSQL JSON fails to convert some Unicode escape sequence to TEXT.
/// Let's replace these unicodes sequences with <NULL> placeholder.
fn escape_unicode_null(string: &str) -> String {
    string
        .split('\\')
        .fold(
            (String::new(), false),
            |(new_string, escape_state), piece| match (piece, escape_state) {
                ("", true) => (new_string + "\\\\", false),
                (s, true) => {
                    if let Some(stripped) = s.strip_prefix("u0000") {
                        (new_string + "<NULL>" + stripped, true)
                    } else {
                        (new_string + "\\" + s, true)
                    }
                }
                (s, false) => (new_string + s, true),
            },
        )
        .0
}

extern "C" fn output_thread_init(
    _data: *const c_void,
    _thread_id: std::os::raw::c_int,
    thread_data: *mut *mut c_void,
) -> c_int {
    // Load configuration
    let config = Config::new();

    // Create thread context
    let (tx, rx) = mpsc::sync_channel(config.buffer);
    let mut database_client = match database::Database::new(&config.database_url, rx) {
        Ok(db) => db,
        Err(err) => panic!("Failed to open database: {err:?}"),
    };
    std::thread::spawn(move || database_client.run());
    let context_ptr = Box::into_raw(Box::new(Context { tx }));

    unsafe {
        *thread_data = context_ptr.cast();
    }
    0
}

extern "C" fn output_thread_deinit(_data: *const c_void, thread_data: *mut c_void) {
    let context = unsafe { Box::from_raw(thread_data as *mut Context) };
    log::debug!("SQL Eve output finished");
    std::mem::drop(context);
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_unicode_null_1() {
        let result = escape_unicode_null("test1\\test2\ntest3\\u0000\\\\u0000");
        assert_eq!(result, "test1\\test2\ntest3<NULL>\\\\u0000");
    }

    #[test]
    fn escape_unicode_null_2() {
        let result = escape_unicode_null("\\u0000\\\\u0000\\\\\\u0000\\\\\\\\u0000");
        assert_eq!(result, "<NULL>\\\\u0000\\\\<NULL>\\\\\\\\u0000");
    }
}
