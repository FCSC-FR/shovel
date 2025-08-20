// Copyright (C) 2025  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::Filedata;
use rusqlite::Transaction;

/// Add one filedata payload to the SQL database
fn write_filedata(
    transaction: &Transaction,
    filedata: &Filedata,
) -> Result<usize, rusqlite::Error> {
    transaction.execute(
        "INSERT OR IGNORE INTO filedata (sha256, blob) values(?, ?)",
        (&filedata.sha256, &filedata.blob),
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
        conn.execute_batch(include_str!("schema.sql"))
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
