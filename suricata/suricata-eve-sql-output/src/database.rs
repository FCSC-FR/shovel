// Copyright (C) 2024  ANSSI
// Copyright (C) 2025-2026  A. Iooss
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
                "INSERT INTO flow (id, ts_start, ts_end, src_ip, src_port, dest_ip, dest_port, proto, app_proto, metadata, extra_data) \
                values ($1->>'flow_id', \
                (UNIXEPOCH(SUBSTR($1->>'$.flow.start', 1, 19))*1000000 + SUBSTR($1->>'$.flow.start', 21, 6)), \
                (UNIXEPOCH(SUBSTR($1->>'$.flow.end', 1, 19))*1000000 + SUBSTR($1->>'$.flow.end', 21, 6)), \
                $2, $1->>'src_port', $3, $1->>'dest_port', $1->>'proto', $1->>'app_proto', jsonb_extract($1, '$.metadata'), jsonb_extract($1, '$.flow')) \
                ON CONFLICT DO NOTHING")
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
            "INSERT INTO 'other-event' (flow_id, timestamp, event_type, extra_data) \
            values ($1->>'flow_id', (UNIXEPOCH(SUBSTR($1->>'timestamp', 1, 19))*1000000 + SUBSTR($1->>'timestamp', 21, 6)), $2, jsonb_extract($1, '$.' || $2)) \
            ON CONFLICT DO NOTHING")
        .bind(buf).bind(event_type).execute(&mut **transaction)
        .await
        .map(|r| r.rows_affected()),
    }
}

pub struct Database {
    runtime: Option<tokio::runtime::Runtime>,
    conn: Option<sqlx::AnyConnection>,
    rx: std::sync::mpsc::Receiver<String>,
    count: u64,
    count_inserted: u64,
}

impl Database {
    /// Init database
    pub fn new(url: &str, rx: std::sync::mpsc::Receiver<String>) -> Result<Self, sqlx::Error> {
        // sqlx requires async runtime
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        sqlx::any::install_default_drivers();
        let conn = runtime.block_on(async {
            let mut conn = {
                // wait for database ready
                let mut maybe_conn: Option<sqlx::AnyConnection> = None;
                while maybe_conn.is_none() {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    maybe_conn = sqlx::AnyConnection::connect(url).await.ok();
                }
                maybe_conn.unwrap() // won't panic
            };
            if conn.backend_name() == "SQLite" {
                sqlx::raw_sql("PRAGMA journal_mode = WAL; PRAGMA synchronous = off")
                    .execute(&mut conn)
                    .await?;
            }
            sqlx::raw_sql(include_str!("schema.sql"))
                .execute(&mut conn)
                .await?;
            Ok::<sqlx::AnyConnection, sqlx::Error>(conn)
        })?;
        Ok(Self {
            runtime: Some(runtime),
            conn: Some(conn),
            rx,
            count: 0,
            count_inserted: 0,
        })
    }

    /// Main worker loop
    async fn batch_write_events(&mut self) -> Result<(), sqlx::Error> {
        // Wait for first event to create a transaction
        while let Ok(buf) = self.rx.recv() {
            let mut transaction = self.conn.as_mut().unwrap().begin().await?;
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
        self.conn.take().unwrap().close().await?;
        Ok(())
    }

    /// Database thread entry
    pub fn run(&mut self) {
        log::debug!("Database thread started");
        let rt = self.runtime.take().unwrap();
        rt.block_on(async {
            if let Err(err) = self.batch_write_events().await {
                log::error!("Failed to write to database: {err:?}");
            }
        });
        log::info!(
            "Database thread finished: count={} inserted={}",
            self.count,
            self.count_inserted
        );
    }
}
