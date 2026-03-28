// Copyright (C) 2024  ANSSI
// Copyright (C) 2025  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use sqlx::{Connection, Transaction};

fn sc_ip_format(sc_ipaddr: &str) -> String {
    match sc_ipaddr.parse() {
        Ok(std::net::IpAddr::V4(ip)) => ip.to_string(),
        Ok(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
        Err(_) => sc_ipaddr.to_string(),
    }
}

/// Add one Eve event to the SQL database
async fn write_event(
    transaction: &mut Transaction<'_, sqlx::Any>,
    buf: &str,
) -> Result<u64, sqlx::Error> {
    // Zero-copy extraction of the event_type
    let event_type = match buf.split_once(r#","event_type":""#) {
        Some((_, p)) => p,
        None => buf.split(r#", "event_type": ""#).nth(1).unwrap_or_default(),
    }
    .split('"')
    .next()
    .unwrap_or("unknown");

    match event_type {
        "flow" => {
            let src_ip_part = buf.split(r#","src_ip":""#).nth(1).unwrap_or_default();
            let src_ip = src_ip_part.split('"').next().unwrap_or("0.0.0.0");
            let dest_ip_part = buf.split(r#","dest_ip":""#).nth(1).unwrap_or_default();
            let dest_ip = dest_ip_part.split('"').next().unwrap_or("0.0.0.0");
            // SQLite UNIXEPOCH currently has only millisecond precision using "subsec", which is not enough
            sqlx::query(
                "INSERT OR IGNORE INTO flow (id, ts_start, ts_end, src_ip, src_port, dest_ip, dest_port, proto, app_proto, metadata, extra_data) \
                values($1->>'flow_id', \
                (UNIXEPOCH(SUBSTR($1->>'$.flow.start', 1, 19))*1000000 + SUBSTR($1->>'$.flow.start', 21, 6)), \
                (UNIXEPOCH(SUBSTR($1->>'$.flow.end', 1, 19))*1000000 + SUBSTR($1->>'$.flow.end', 21, 6)), \
                $2, $1->>'src_port', $3, $1->>'dest_port', $1->>'proto', $1->>'app_proto', jsonb_extract($1, '$.metadata'), jsonb_extract($1, '$.flow'))")
            .bind(buf)
            .bind(sc_ip_format(src_ip))
            .bind(sc_ip_format(dest_ip))
            .execute(&mut **transaction)
            .await
            .map(|r| r.rows_affected())
        },
        "alert" => sqlx::query(
            "WITH vars AS (SELECT jsonb_extract($1, '$.' || $2) AS extra_data) \
            INSERT OR IGNORE INTO alert (flow_id, tag, color, timestamp, extra_data) \
            SELECT $1->>'flow_id', (vars.extra_data->>'$.metadata.tag[0]'), (vars.extra_data->>'$.metadata.color[0]'), (UNIXEPOCH(SUBSTR($1->>'timestamp', 1, 19))*1000000 + SUBSTR($1->>'timestamp', 21, 6)), vars.extra_data \
            FROM vars")
        .bind(buf)
        .bind(event_type).execute(&mut **transaction)
        .await
        .map(|r| r.rows_affected()),
        _ => sqlx::query(
            "INSERT OR IGNORE INTO 'other-event' (flow_id, timestamp, event_type, extra_data) \
            values($1->>'flow_id', (UNIXEPOCH(SUBSTR($1->>'timestamp', 1, 19))*1000000 + SUBSTR($1->>'timestamp', 21, 6)), $2, jsonb_extract($1, '$.' || $2))")
        .bind(buf).bind(event_type).execute(&mut **transaction)
        .await
        .map(|r| r.rows_affected()),
    }
}

pub struct Database {
    url: String,
    rx: std::sync::mpsc::Receiver<String>,
    count: u64,
    count_inserted: u64,
}

impl Database {
    pub fn new(url: String, rx: std::sync::mpsc::Receiver<String>) -> Self {
        Self {
            url,
            rx,
            count: 0,
            count_inserted: 0,
        }
    }

    async fn batch_write_events(&mut self) -> Result<(), sqlx::Error> {
        // Init database
        sqlx::any::install_default_drivers();
        let mut conn = sqlx::AnyConnection::connect(&self.url).await?;
        if conn.backend_name() == "SQLite" {
            sqlx::raw_sql("PRAGMA journal_mode = WAL; PRAGMA synchronous = off")
                .execute(&mut conn)
                .await?;
        }
        sqlx::query(include_str!("schema.sql"))
            .execute(&mut conn)
            .await?;

        // Wait for first event to create a transaction
        while let Ok(buf) = self.rx.recv() {
            let mut transaction = conn.begin().await?;
            self.count = self.count.saturating_add(1);
            let inserted = write_event(&mut transaction, &buf).await?;
            self.count_inserted = self.count_inserted.saturating_add(inserted);

            // Insert currently pending events
            while let Ok(rawdata) = self.rx.try_recv() {
                self.count = self.count.saturating_add(1);
                let inserted = write_event(&mut transaction, &rawdata).await?;
                self.count_inserted = self.count_inserted.saturating_add(inserted);
            }

            transaction.commit().await?;
        }
        conn.close().await?;
        Ok(())
    }

    /// Database thread entry
    pub fn run(&mut self) {
        log::debug!("Database thread started");
        // sqlx requires async runtime
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread().build() {
            rt.block_on(async {
                if let Err(err) = self.batch_write_events().await {
                    log::error!("Failed to write to database {}: {err:?}", self.url);
                }
            });
        }
        log::info!(
            "Database thread finished: count={} inserted={}",
            self.count,
            self.count_inserted
        );
    }
}
