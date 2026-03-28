// Copyright (C) 2025  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt::Write as _;
use std::io::Write as _;

use crate::Filedata;
use sqlx::{Connection, Transaction};

// SQLar format as specified at https://sqlite.org/sqlar.html
const SQLAR_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sqlar (
    name TEXT PRIMARY KEY,
    mode INT,               -- access permissions
    mtime INT,              -- last modification time
    sz INT,                 -- original file size
    data BLOB               -- compressed content
);";

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
    // 33188 = 0o100_644
    sqlx::query(
        "INSERT OR IGNORE INTO sqlar (name, mode, mtime, sz, data) values($1, 33188, 0, $2, $3)",
    )
    .bind(name)
    .bind(original_size)
    .bind(data)
    .execute(&mut **transaction)
    .await
    .map(|r| r.rows_affected())
}

pub struct Database {
    url: String,
    rx: std::sync::mpsc::Receiver<Filedata>,
    count: u64,
    count_inserted: u64,
}

impl Database {
    pub fn new(url: String, rx: std::sync::mpsc::Receiver<Filedata>) -> Self {
        Self {
            url,
            rx,
            count: 0,
            count_inserted: 0,
        }
    }

    async fn batch_write_filedata(&mut self) -> Result<(), sqlx::Error> {
        // Init database
        sqlx::any::install_default_drivers();
        let mut conn = sqlx::AnyConnection::connect(&self.url).await?;
        if conn.backend_name() == "SQLite" {
            sqlx::raw_sql("PRAGMA journal_mode = WAL; PRAGMA synchronous = off")
                .execute(&mut conn)
                .await?;
        }
        sqlx::query(SQLAR_SCHEMA).execute(&mut conn).await?;

        // Wait for first filedata to create a transaction
        while let Ok(filedata) = self.rx.recv() {
            let mut transaction = conn.begin().await?;
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
        conn.close().await?;
        Ok(())
    }

    /// Database thread entry
    pub fn run(&mut self) {
        log::debug!("Database thread started");
        // sqlx requires async runtime
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread().build() {
            rt.block_on(async {
                if let Err(err) = self.batch_write_filedata().await {
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
