// Copyright (C) 2026  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::Rawdata;
use rusqlite::Transaction;

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
fn write_rawdata(transaction: &Transaction, rd: &Rawdata) -> Result<usize, rusqlite::Error> {
    transaction.execute(
        "INSERT OR IGNORE INTO raw (flow_id, count, direction, data) values(?, ?, ?, ?)",
        (
            rd.flow_id,
            rd.packet_count,
            rd.direction,
            &rd.data,
        ),
    )
}

pub struct Database {
    conn: Option<rusqlite::Connection>,
    rx: std::sync::mpsc::Receiver<Rawdata>,
    count: usize,
    count_inserted: usize,
}

impl Database {
    /// Open SQLite database connection in WAL journal mode then init schema
    pub fn new(
        filename: String,
        rx: std::sync::mpsc::Receiver<Rawdata>,
    ) -> Result<Self, rusqlite::Error> {
        let conn = rusqlite::Connection::open(filename)?;
        conn.pragma_update(None, "journal_mode", "wal")?;
        conn.pragma_update(None, "synchronous", "off")?;
        conn.execute_batch(SQL_SCHEMA)?;
        Ok(Self {
            conn: Some(conn),
            rx,
            count: 0,
            count_inserted: 0,
        })
    }

    fn batch_write_rawdata(&mut self) -> Result<(), rusqlite::Error> {
        if let Some(mut conn) = self.conn.take() {
            while let Ok(rawdata) = self.rx.recv() {
                let transaction = conn.transaction()?;

                // Insert first raw payload
                self.count = self.count.saturating_add(1);
                let inserted = write_rawdata(&transaction, &rawdata)?;
                self.count_inserted = self.count_inserted.saturating_add(inserted);

                // Insert remaining raw payloads
                let batch = self
                    .rx
                    .try_iter()
                    .map(|rawdata| write_rawdata(&transaction, &rawdata))
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
        if let Err(err) = self.batch_write_rawdata() {
            log::error!("Failed to write to database: {err:?}");
        }
        log::info!(
            "Database thread finished: count={} inserted={}",
            self.count,
            self.count_inserted
        );
    }
}
