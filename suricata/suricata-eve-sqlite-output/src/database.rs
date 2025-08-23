// Copyright (C) 2024  ANSSI
// Copyright (C) 2025  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use rusqlite::Transaction;

fn sc_ip_format(sc_ipaddr: &str) -> String {
    match sc_ipaddr.parse().expect("invalid IP address") {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

/// Add one Eve event to the SQL database
fn write_event(transaction: &Transaction, buf: &str) -> Result<usize, rusqlite::Error> {
    // Zero-copy extraction of the event_type
    let (event_type, _) = match buf.split_once(r#","event_type":""#) {
        Some((_, p)) => p,
        None => {
            buf.split_once(r#", "event_type": ""#)
                .expect("missing event_type")
                .1
        }
    }
    .split_once('"')
    .unwrap();

    match event_type {
        "flow" => {
            let (_, src_ip_part) = buf.split_once(r#","src_ip":""#).expect("missing src_ip");
            let (src_ip, _) = src_ip_part.split_once('"').unwrap();
            let (_, dest_ip_part) = buf.split_once(r#","dest_ip":""#).expect("missing dest_ip");
            let (dest_ip, _) = dest_ip_part.split_once('"').unwrap();
            // SQLite UNIXEPOCH currently has only millisecond precision using "subsec", which is not enough
            transaction.execute(
                "INSERT OR IGNORE INTO flow (id, ts_start, ts_end, src_ip, src_port, dest_ip, dest_port, proto, app_proto, metadata, extra_data) \
                values(?1->>'flow_id', \
                (UNIXEPOCH(SUBSTR(?1->>'$.flow.start', 1, 19))*1000000 + SUBSTR(?1->>'$.flow.start', 21, 6)), \
                (UNIXEPOCH(SUBSTR(?1->>'$.flow.end', 1, 19))*1000000 + SUBSTR(?1->>'$.flow.end', 21, 6)), \
                ?2, ?1->>'src_port', ?3, ?1->>'dest_port', ?1->>'proto', ?1->>'app_proto', jsonb_extract(?1, '$.metadata'), jsonb_extract(?1, '$.flow'))",
                (buf, sc_ip_format(src_ip), sc_ip_format(dest_ip)),
            )
        },
        "alert" => transaction.execute(
            "WITH vars AS (SELECT jsonb_extract(?1, '$.' || ?2) AS extra_data) \
            INSERT OR IGNORE INTO alert (flow_id, tag, color, timestamp, extra_data) \
            SELECT ?1->>'flow_id', (vars.extra_data->>'$.metadata.tag[0]'), (vars.extra_data->>'$.metadata.color[0]'), (UNIXEPOCH(SUBSTR(?1->>'timestamp', 1, 19))*1000000 + SUBSTR(?1->>'timestamp', 21, 6)), vars.extra_data \
            FROM vars",
            (buf, event_type),
        ),
        _ => transaction.execute(
            "INSERT OR IGNORE INTO 'other-event' (flow_id, timestamp, event_type, extra_data) \
            values(?1->>'flow_id', (UNIXEPOCH(SUBSTR(?1->>'timestamp', 1, 19))*1000000 + SUBSTR(?1->>'timestamp', 21, 6)), ?2, jsonb_extract(?1, '$.' || ?2))",
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
