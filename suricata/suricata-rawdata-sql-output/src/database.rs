// Copyright (C) 2026  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::Rawdata;
use sqlx::{Connection, Transaction};

const SQL_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS raw (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL,
    count INTEGER,
    direction INTEGER,
    data BLOB,
    UNIQUE(flow_id, count)
);
CREATE INDEX IF NOT EXISTS raw_flow_id_idx ON raw(flow_id);";

/// Add one raw payload to the SQL database
async fn write_rawdata(
    transaction: &mut Transaction<'_, sqlx::Any>,
    rd: &Rawdata,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "INSERT INTO raw (flow_id, count, direction, data) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(rd.flow_id)
    .bind(rd.packet_count)
    .bind(rd.direction)
    .bind(&rd.data)
    .execute(&mut **transaction)
    .await
    .map(|r| r.rows_affected())
}

pub struct Database {
    url: String,
    rx: std::sync::mpsc::Receiver<Rawdata>,
    count: u64,
    count_inserted: u64,
}

impl Database {
    pub fn new(url: String, rx: std::sync::mpsc::Receiver<Rawdata>) -> Self {
        Self {
            url,
            rx,
            count: 0,
            count_inserted: 0,
        }
    }

    async fn batch_write_rawdata(&mut self) -> Result<(), sqlx::Error> {
        // Init database
        sqlx::any::install_default_drivers();
        let mut conn = sqlx::AnyConnection::connect(&self.url).await?;
        if conn.backend_name() == "SQLite" {
            sqlx::raw_sql("PRAGMA journal_mode = WAL; PRAGMA synchronous = off")
                .execute(&mut conn)
                .await?;
        }
        sqlx::query(SQL_SCHEMA).execute(&mut conn).await?;

        // Wait for first raw payload to create a transaction
        while let Ok(rawdata) = self.rx.recv() {
            let mut transaction = conn.begin().await?;
            self.count = self.count.saturating_add(1);
            let inserted = write_rawdata(&mut transaction, &rawdata).await?;
            self.count_inserted = self.count_inserted.saturating_add(inserted);

            // Insert currently pending raw payloads
            while let Ok(rawdata) = self.rx.try_recv() {
                self.count = self.count.saturating_add(1);
                let inserted = write_rawdata(&mut transaction, &rawdata).await?;
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
                if let Err(err) = self.batch_write_rawdata().await {
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
