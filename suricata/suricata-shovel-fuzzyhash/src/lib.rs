// Copyright (C) 2026  A. Iooss
// SPDX-License-Identifier: GPL-2.0-or-later

use suricata_sys::sys::{SC_API_VERSION, SC_PACKAGE_VERSION, SCPlugin};

use sqlx::Connection;
use sqlx::Row;

const SQL_SCHEMA: &str = r#"CREATE TABLE IF NOT EXISTS "flow-fuzzyhash" (
    flow_id BIGINT PRIMARY KEY,
    fuzzyhash TEXT NOT NULL
);"#;

async fn hash_new_flows(conn: &mut sqlx::postgres::PgConnection) -> Result<u64, sqlx::Error> {
    // Find 50 flows that haven't been hashed yet
    // For each flow, concat all filedata if exists, or fallback and concat all rawdata
    let rows = match sqlx::query(
        r#"(
            SELECT e.flow_id, STRING_AGG(f.data, ''::bytea ORDER BY e.timestamp) AS data FROM "other-event" e JOIN filedata f ON f.name = e.extra_data->>'sha256'
            WHERE event_type = 'fileinfo'
            AND NOT EXISTS (SELECT 1 FROM "flow-fuzzyhash" ff WHERE ff.flow_id = e.flow_id)
            GROUP BY e.flow_id
        ) UNION ALL (
            SELECT r.flow_id, STRING_AGG(r.data, ''::bytea ORDER BY count) AS data FROM rawdata r
            WHERE NOT EXISTS (SELECT 1 FROM "flow-fuzzyhash" ff WHERE ff.flow_id = r.flow_id)
            AND NOT EXISTS (SELECT 1 FROM "other-event" e WHERE e.event_type = 'fileinfo' AND e.flow_id = r.flow_id)
            GROUP BY r.flow_id
        ) LIMIT 50"#,
    )
    .fetch_all(&mut *conn)
    .await {
        Err(_) => {
            log::warn!("read query failed, maybe flow table is not yet initialized");
            return Ok(0);
        }
        Ok(r) => r
    };
    if rows.is_empty() {
        return Ok(0);
    }

    // Hash flows
    let mut ids = vec![];
    let mut hashs = vec![];
    for row in &rows {
        let flow_id: i64 = row.try_get("flow_id")?;
        let data_opt: Option<&[u8]> = row.try_get("data")?;
        if let Some(data) = data_opt {
            let mut generator = ssdeep::Generator::new();
            generator.update(data);
            let hash: ssdeep::RawFuzzyHash = generator.finalize().unwrap();
            ids.extend(Some(flow_id));
            hashs.extend(Some(hash.to_string()));
        }
    }

    // Batch insert
    let mut transaction = conn.begin().await?;
    let count = sqlx::query(
        r#"INSERT INTO "flow-fuzzyhash" (flow_id, fuzzyhash)
        SELECT id, hash
        FROM UNNEST($1::bigint[], $2::text[]) AS _(id, hash) ON CONFLICT DO NOTHING"#,
    )
    .bind(&ids)
    .bind(&hashs)
    .execute(&mut *transaction)
    .await
    .map(|r| r.rows_affected())?;
    transaction.commit().await?;

    Ok(count)
}

async fn main() -> Result<(), sqlx::Error> {
    // Open database
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    log::info!("Connecting to PostgreSQL...");
    let mut conn = {
        let mut maybe_conn: Option<sqlx::postgres::PgConnection> = None;
        while maybe_conn.is_none() {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            maybe_conn = sqlx::postgres::PgConnection::connect(&database_url)
                .await
                .ok();
        }
        maybe_conn.unwrap() // won't panic
    };
    log::info!("Connected to PostgreSQL");

    // Make sure flow-fuzzyhash table exists
    sqlx::raw_sql(SQL_SCHEMA).execute(&mut conn).await?;

    let mut total: u64 = 0;
    loop {
        match hash_new_flows(&mut conn).await? {
            // poll every seconds
            0 => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
            count => {
                total = total.saturating_add(count);
                log::debug!("Hashed {count} flows (total {total})")
            }
        }
    }
}

extern "C" fn plugin_init() {
    // Init Rust logger
    // don't log using `suricata` crate to reduce build time.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            if let Err(err) = main().await {
                log::error!("shovel-fuzzyhash ended with error {err:?}");
            }
        });
    });
}

/// Plugin entrypoint, registers [`plugin_init`] function in Suricata
#[unsafe(no_mangle)]
extern "C" fn SCPluginRegister() -> *const SCPlugin {
    let plugin = SCPlugin {
        version: SC_API_VERSION,
        suricata_version: SC_PACKAGE_VERSION.as_ptr().cast::<::std::os::raw::c_char>(),
        name: c"Shovel Fuzzyhash".as_ptr(),
        plugin_version: c"0.1.0".as_ptr(),
        license: c"GPL-2.0".as_ptr(),
        author: c"ECSC TeamFrance".as_ptr(),
        Init: Some(plugin_init),
    };
    Box::into_raw(Box::new(plugin))
}
