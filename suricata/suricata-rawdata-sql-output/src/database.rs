// Copyright (C) 2026  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::Rawdata;
use sqlx::{Connection, Transaction};

const SQL_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS rawdata (
    flow_id BIGINT NOT NULL,
    count INTEGER NOT NULL,
    direction INTEGER,
    data BYTEA,
    PRIMARY KEY(flow_id, count)
);
CREATE INDEX IF NOT EXISTS rawdata_flow_id_idx ON rawdata(flow_id);";

/// Add one raw payload to the SQL database
async fn write_rawdata(
    transaction: &mut Transaction<'_, sqlx::Any>,
    rd: &Rawdata,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "INSERT INTO rawdata (flow_id, count, direction, data) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
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
    runtime: Option<tokio::runtime::Runtime>,
    conn: Option<sqlx::AnyConnection>,
    rx: std::sync::mpsc::Receiver<Rawdata>,
    count: u64,
    count_inserted: u64,
}

impl Database {
    /// Init database
    pub fn new(url: &str, rx: std::sync::mpsc::Receiver<Rawdata>) -> Result<Self, sqlx::Error> {
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
            sqlx::raw_sql(SQL_SCHEMA).execute(&mut conn).await?;
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
    async fn batch_write_rawdata(&mut self) -> Result<(), sqlx::Error> {
        // Wait for first raw payload to create a transaction
        while let Ok(rawdata) = self.rx.recv() {
            let mut transaction = self.conn.as_mut().unwrap().begin().await?;
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
        self.conn.take().unwrap().close().await?;
        Ok(())
    }

    /// Database thread entry
    pub fn run(&mut self) {
        log::debug!("Database thread started");
        let rt = self.runtime.take().unwrap();
        rt.block_on(async {
            if let Err(err) = self.batch_write_rawdata().await {
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
