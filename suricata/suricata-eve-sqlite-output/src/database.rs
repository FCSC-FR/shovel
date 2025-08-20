// Copyright (C) 2024  ANSSI
// Copyright (C) 2025  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use regex_lite::Regex;
use rusqlite::Transaction;
use std::sync::LazyLock;

static RE_EVENT_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""event_type":"([^"]+)""#).unwrap());
static RE_SRC_IP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""src_ip":"([^"]+)""#).unwrap());
static RE_DEST_IP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""dest_ip":"([^"]+)""#).unwrap());

fn sc_ip_format(sc_ipaddr: String) -> String {
    match sc_ipaddr.parse().expect("invalid IP address") {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

/// Add one Eve event to the SQL database
fn write_event(transaction: &Transaction, buf: &str) -> Result<usize, rusqlite::Error> {
    // Use regex rather than JSON parsing for performance reasons.
    // Ignore events that don't have event_type field, such as stats.
    let Some(event_type_caps) = RE_EVENT_TYPE.captures(buf) else {
        return Ok(0);
    };
    let event_type = &event_type_caps[1];

    match event_type {
        "flow" => {
            let src_ip = &RE_SRC_IP.captures(buf).expect("missing src_ip")[1];
            let dest_ip = &RE_DEST_IP.captures(buf).expect("missing dest_ip")[1];
            transaction.execute(
                "INSERT OR IGNORE INTO flow (id, src_ip, src_port, dest_ip, dest_port, proto, app_proto, metadata, extra_data) \
                values(?1->>'flow_id', ?2, ?1->>'src_port', ?3, ?1->>'dest_port', ?1->>'proto', ?1->>'app_proto', ?1->'metadata', ?1->'flow')",
                (buf, sc_ip_format(src_ip.to_string()), sc_ip_format(dest_ip.to_string())),
            )
        },
        "alert" => transaction.execute(
            "INSERT OR IGNORE INTO alert (flow_id, timestamp, extra_data) \
            values(?1->>'flow_id', (UNIXEPOCH(SUBSTR(?1->>'timestamp', 1, 19))*1000000 + SUBSTR(?1->>'timestamp', 21, 6)), json_extract(?1, '$.' || ?2))",
            (buf, event_type),
        ),
        _ => transaction.execute(
            "INSERT OR IGNORE INTO 'other-event' (flow_id, timestamp, event_type, extra_data) \
            values(?1->>'flow_id', (UNIXEPOCH(SUBSTR(?1->>'timestamp', 1, 19))*1000000 + SUBSTR(?1->>'timestamp', 21, 6)), ?2, json_extract(?1, '$.' || ?2))",
            (buf, event_type),
        )
    }
}

pub struct Database {
    conn: Option<rusqlite::Connection>,
    rx: std::sync::mpsc::Receiver<String>,
    count: usize,
    count_inserted: usize,
}

impl Database {
    /// Open SQLite database connection in WAL journal mode then init schema
    pub fn new(
        filename: String,
        rx: std::sync::mpsc::Receiver<String>,
    ) -> Result<Self, rusqlite::Error> {
        let conn = rusqlite::Connection::open(filename)?;
        conn.pragma_update(None, "journal_mode", "wal")
            .expect("Failed to set journal_mode=wal");
        conn.pragma_update(None, "synchronous", "off")
            .expect("Failed to set synchronous=off");
        conn.execute_batch(include_str!("schema.sql"))
            .expect("Failed to initialize database schema");
        Ok(Self {
            conn: Some(conn),
            rx,
            count: 0,
            count_inserted: 0,
        })
    }

    fn batch_write_events(&mut self) -> Result<(), rusqlite::Error> {
        // This unwrap will never fails as conn must be initialized before this call
        let db_conn = self.conn.as_mut().unwrap();
        while let Ok(buf) = self.rx.recv() {
            let transaction = db_conn.transaction()?;

            // Insert first event
            self.count += 1;
            self.count_inserted += write_event(&transaction, &buf)?;

            // Insert remaining events
            let batch = self
                .rx
                .try_iter()
                .map(|buf| write_event(&transaction, &buf))
                .collect::<Result<Vec<_>, _>>()?;
            self.count += batch.len();
            self.count_inserted += batch.iter().sum::<usize>();

            transaction.commit()?;
        }
        self.conn.take().unwrap().close().map_err(|(_, err)| err)
    }

    /// Database thread entry
    pub fn run(&mut self) {
        log::debug!("Database thread started");
        if let Err(err) = self.batch_write_events() {
            log::error!("Failed to write to database: {err:?}");
        }
        log::info!(
            "Database thread finished: count={} inserted={}",
            self.count,
            self.count_inserted
        );
    }
}
