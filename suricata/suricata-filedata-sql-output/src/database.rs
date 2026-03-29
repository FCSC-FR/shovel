// Copyright (C) 2025-2026  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt::Write as _;
use std::io::Write as _;

use crate::Filedata;
use sqlx::{Connection, Transaction};

const SQL_SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS filedata (name TEXT PRIMARY KEY, sz INT, data BYTEA);";

/// Add one filedata payload to the SQLar archive
async fn write_filedata(
    transaction: &mut Transaction<'_, sqlx::Any>,
    filedata: &Filedata,
) -> Result<u64, sqlx::Error> {
    let name = filedata.sha256.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    });
    let original_size: i64 = filedata.blob.len().try_into().unwrap_or(0);
    let data = if original_size < 256 {
        // Do not compress smaller blobs
        &filedata.blob
    } else {
        // Compress using deflate
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        match e.write_all(&filedata.blob) {
            Ok(()) => &e.finish().unwrap_or_else(|_| filedata.blob.clone()),
            Err(_) => &filedata.blob,
        }
    };
    sqlx::query("INSERT INTO filedata (name, sz, data) values ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(name)
        .bind(original_size)
        .bind(data)
        .execute(&mut **transaction)
        .await
        .map(|r| r.rows_affected())
}

pub struct Database {
    runtime: Option<tokio::runtime::Runtime>,
    conn: Option<sqlx::AnyConnection>,
    rx: std::sync::mpsc::Receiver<Filedata>,
    count: u64,
    count_inserted: u64,
}

impl Database {
    /// Init database
    pub fn new(url: &str, rx: std::sync::mpsc::Receiver<Filedata>) -> Result<Self, sqlx::Error> {
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
    async fn batch_write_filedata(&mut self) -> Result<(), sqlx::Error> {
        // Wait for first filedata to create a transaction
        while let Ok(filedata) = self.rx.recv() {
            let mut transaction = self.conn.as_mut().unwrap().begin().await?;
            self.count = self.count.saturating_add(1);
            let inserted = write_filedata(&mut transaction, &filedata).await?;
            self.count_inserted = self.count_inserted.saturating_add(inserted);

            // Insert currently pending filedata
            while let Ok(rawdata) = self.rx.try_recv() {
                self.count = self.count.saturating_add(1);
                let inserted = write_filedata(&mut transaction, &rawdata).await?;
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
            if let Err(err) = self.batch_write_filedata().await {
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
