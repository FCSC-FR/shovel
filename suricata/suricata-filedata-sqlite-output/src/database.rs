// Copyright (C) 2025  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt::Write as _;
use std::io::Write as _;

use crate::Filedata;
use rusqlite::Transaction;

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
fn write_filedata(
    transaction: &Transaction,
    filedata: &Filedata,
) -> Result<usize, rusqlite::Error> {
    let name = filedata.sha256.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    });
    let original_size: u32 = filedata.blob.len().try_into().unwrap_or(0);
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
    transaction.execute(
        "INSERT OR IGNORE INTO sqlar (name, mode, mtime, sz, data) values(?, ?, ?, ?, ?)",
        (name, 0o100_644, 0, original_size, &data),
    )
}

pub struct Database {
    conn: Option<rusqlite::Connection>,
    rx: std::sync::mpsc::Receiver<Filedata>,
    count: usize,
    count_inserted: usize,
}

impl Database {
    /// Open SQLite database connection in WAL journal mode then init schema
    pub fn new(
        filename: String,
        rx: std::sync::mpsc::Receiver<Filedata>,
    ) -> Result<Self, rusqlite::Error> {
        let conn = rusqlite::Connection::open(filename)?;
        conn.pragma_update(None, "journal_mode", "wal")?;
        conn.pragma_update(None, "synchronous", "off")?;
        conn.execute_batch(SQLAR_SCHEMA)?;
        Ok(Self {
            conn: Some(conn),
            rx,
            count: 0,
            count_inserted: 0,
        })
    }

    fn batch_write_filedata(&mut self) -> Result<(), rusqlite::Error> {
        if let Some(mut conn) = self.conn.take() {
            while let Ok(filedata) = self.rx.recv() {
                let transaction = conn.transaction()?;

                // Insert first filedata
                self.count = self.count.saturating_add(1);
                let inserted = write_filedata(&transaction, &filedata)?;
                self.count_inserted = self.count_inserted.saturating_add(inserted);

                // Insert remaining filedata
                let batch = self
                    .rx
                    .try_iter()
                    .map(|filedata| write_filedata(&transaction, &filedata))
                    .collect::<Result<Vec<_>, _>>()?;
                self.count = self.count.saturating_add(batch.len());
                self.count_inserted = self
                    .count_inserted
                    .saturating_add(batch.iter().sum::<usize>());

                transaction.commit()?;
            }
            conn.close().map_err(|(_, err)| err)?;
        }
        Ok(())
    }

    /// Database thread entry
    pub fn run(&mut self) {
        log::debug!("Database thread started");
        if let Err(err) = self.batch_write_filedata() {
            log::error!("Failed to write to database: {err:?}");
        }
        log::info!(
            "Database thread finished: count={} inserted={}",
            self.count,
            self.count_inserted
        );
    }
}
