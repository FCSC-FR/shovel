// Copyright (C) 2025  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use std::io::Write;

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
    let name: String = filedata
        .sha256
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();
    let original_size: u32 = filedata.blob.len().try_into().unwrap_or(0);
    let data = if original_size < 256 {
        // Do not compress smaller blobs
        &filedata.blob
    } else {
        // Compress using deflate
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(&filedata.blob).unwrap();
        &e.finish().unwrap()
    };
    transaction.execute(
        "INSERT OR IGNORE INTO sqlar (name, mode, mtime, sz, data) values(?, ?, ?, ?, ?)",
        (name, 0o100644, 0, original_size, &data),
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
        conn.pragma_update(None, "journal_mode", "wal")
            .expect("Failed to set journal_mode=wal");
        conn.pragma_update(None, "synchronous", "off")
            .expect("Failed to set synchronous=off");
        conn.execute_batch(SQLAR_SCHEMA)
            .expect("Failed to initialize database schema");
        Ok(Self {
            conn: Some(conn),
            rx,
            count: 0,
            count_inserted: 0,
        })
    }

    fn batch_write_filedata(&mut self) -> Result<(), rusqlite::Error> {
        // This unwrap will never fails as conn must be initialized before this call
        let db_conn = self.conn.as_mut().unwrap();
        while let Ok(filedata) = self.rx.recv() {
            let transaction = db_conn.transaction()?;

            // Insert first filedata
            self.count += 1;
            self.count_inserted += write_filedata(&transaction, &filedata)?;

            // Insert remaining filedata
            let batch = self
                .rx
                .try_iter()
                .map(|filedata| write_filedata(&transaction, &filedata))
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
