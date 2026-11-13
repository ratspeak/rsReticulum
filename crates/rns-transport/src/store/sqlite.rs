//! SQLite stores. Schema, pragmas and `user_version` follow `RNS/Storage.py`
//! at Reticulum 1.6.0 (`KnownDestinationsStore`, `AnnounceCache`).

use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, Statement, params};
use tracing::warn;

use super::{
    ANNOUNCE_CACHE_USER_VERSION, AnnounceCacheStore, AnnounceFacts, AnnounceRow, ApplyReport,
    CHUNK_ROWS, CachedAnnounce, DestHash, KNOWN_DESTINATIONS_USER_VERSION, KdBatch,
    KnownDestinationRow, KnownDestinationStore, PacketHash, Ratchet, RatchetRow, RejectedTable,
    Rejection, StoreError,
};

const KD_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS known_destinations (
    destination_hash BLOB PRIMARY KEY,
    last_heard       REAL NOT NULL,
    packet_hash      BLOB,
    public_key       BLOB NOT NULL,
    app_data         BLOB,
    used             REAL NOT NULL DEFAULT 0,
    stamp            BLOB,
    stamp_value      REAL,
    lr_cost          REAL,
    identity_hash    BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS ratchets (
    destination_hash BLOB PRIMARY KEY,
    ratchet          BLOB NOT NULL,
    received         REAL NOT NULL);
CREATE TABLE IF NOT EXISTS rs_announce_facts (
    destination_hash BLOB PRIMARY KEY,
    last_heard       REAL NOT NULL,
    hops             INTEGER NOT NULL,
    name_hash        BLOB NOT NULL,
    path_response    INTEGER NOT NULL);";

// `rs_announce_facts` is this crate's own table; upstream neither reads nor
// drops it. A row counts only while `last_heard` equals its destination's, so
// one upstream has replaced or deleted since reads as unknown.
const FACTS_UPSERT_SQL: &str = "INSERT INTO rs_announce_facts VALUES (?,?,?,?,?) ON CONFLICT(destination_hash) DO UPDATE SET last_heard=excluded.last_heard, hops=excluded.hops, name_hash=excluded.name_hash, path_response=excluded.path_response";
const FACTS_DELETE_SQL: &str = "DELETE FROM rs_announce_facts WHERE destination_hash=?";
const FACTS_PRUNE_SQL: &str = "DELETE FROM rs_announce_facts WHERE NOT EXISTS (SELECT 1 FROM known_destinations k WHERE k.destination_hash = rs_announce_facts.destination_hash AND k.last_heard = rs_announce_facts.last_heard)";
const KD_SELECT_SQL: &str = "SELECT destination_hash, last_heard, packet_hash, public_key, app_data, used, stamp, stamp_value, lr_cost FROM known_destinations";
const KD_SELECT_WITH_FACTS_SQL: &str = "SELECT k.destination_hash, k.last_heard, k.packet_hash, k.public_key, k.app_data, k.used, k.stamp, k.stamp_value, k.lr_cost, f.hops, f.name_hash, f.path_response FROM known_destinations k LEFT JOIN rs_announce_facts f ON f.destination_hash = k.destination_hash AND f.last_heard = k.last_heard";

const KD_UPSERT_SQL: &str = "INSERT INTO known_destinations (destination_hash, last_heard, packet_hash, public_key, app_data, used, stamp, stamp_value, lr_cost, identity_hash) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(destination_hash) DO UPDATE SET last_heard=excluded.last_heard, packet_hash=excluded.packet_hash, public_key=excluded.public_key, app_data=excluded.app_data, used=excluded.used, stamp=excluded.stamp, stamp_value=excluded.stamp_value, lr_cost=excluded.lr_cost, identity_hash=excluded.identity_hash";
const KD_DELETE_SQL: &str = "DELETE FROM known_destinations WHERE destination_hash=?";
const RATCHET_UPSERT_SQL: &str = "INSERT INTO ratchets VALUES (?,?,?) ON CONFLICT(destination_hash) DO UPDATE SET ratchet=excluded.ratchet, received=excluded.received";
const RATCHET_DELETE_SQL: &str = "DELETE FROM ratchets WHERE destination_hash=?";

const ANNOUNCE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS cached_announces (
    packet_hash         BLOB PRIMARY KEY,
    received            REAL NOT NULL,
    raw                 BLOB NOT NULL,
    interface_reference TEXT)";
const ANNOUNCE_UPSERT_SQL: &str = "INSERT INTO cached_announces VALUES (?,?,?,?) ON CONFLICT(packet_hash) DO UPDATE SET received=excluded.received, raw=excluded.raw, interface_reference=excluded.interface_reference";

/// CPython's `sqlite3.connect` default timeout, which `KnownDestinationsStore.__init__` in
/// `RNS/Storage.py` keeps; stores run on a worker thread, never the transport actor.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

fn with_busy_timeout(conn: Connection) -> Result<Connection, StoreError> {
    db(conn.busy_timeout(BUSY_TIMEOUT))?;
    Ok(conn)
}

/// Maps a rusqlite error to the caller-facing error. Busy and locked are distinct
/// so the caller can retry later.
fn db<T>(result: rusqlite::Result<T>) -> Result<T, StoreError> {
    result.map_err(|e| match &e {
        rusqlite::Error::SqliteFailure(err, _)
            if matches!(
                err.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            ) =>
        {
            StoreError::Locked
        }
        _ => StoreError::Backend(e.to_string()),
    })
}

/// Errors that Python's sqlite3 raises as `IntegrityError` or `DataError`, which
/// upstream quarantines row by row instead of failing the transaction.
fn is_row_error(e: &rusqlite::Error) -> bool {
    match e {
        rusqlite::Error::SqliteFailure(err, _) => matches!(
            err.code,
            ErrorCode::ConstraintViolation | ErrorCode::TypeMismatch | ErrorCode::TooBig
        ),
        _ => false,
    }
}

fn fixed<const N: usize>(bytes: Vec<u8>, table: &'static str) -> Result<[u8; N], StoreError> {
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| StoreError::CorruptRow {
            table,
            reason: format!("expected {N} bytes, found {}", v.len()),
        })
}

fn identity_hash(public_key: &[u8; 64]) -> [u8; 16] {
    let digest = rns_crypto::sha::sha256(public_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn uri_path(path: &Path) -> Result<String, StoreError> {
    let text = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "database path is not valid UTF-8",
        )
    })?;
    Ok(text
        .replace('%', "%25")
        .replace('?', "%3f")
        .replace('#', "%23"))
}

/// Opens read-write and writes the schema at `supported`. `user_version` is read
/// before any pragma or write, and again inside the write lock, so a newer file is
/// refused and keeps its bytes, unless `rebuild` names the statement that clears
/// its tables (`KnownDestinationsStore.__create_schema` drops `known_destinations`).
/// `pragmas` run before the transaction because `auto_vacuum` is ignored inside one.
fn open_rw_checked(
    path: &Path,
    supported: i64,
    pragmas: &str,
    schema: &str,
    rebuild: Option<&str>,
) -> Result<Connection, StoreError> {
    let conn = with_busy_timeout(db(Connection::open(path))?)?;
    let version = |conn: &Connection| -> Result<i64, StoreError> {
        db(conn.pragma_query_value(None, "user_version", |r| r.get(0)))
    };
    let found = version(&conn)?;
    if found > supported && rebuild.is_none() {
        return Err(StoreError::NewerVersion { found, supported });
    }
    db(conn.execute_batch(pragmas))?;
    db(conn.execute_batch("BEGIN IMMEDIATE"))?;
    let result = version(&conn).and_then(|found| {
        if found > supported {
            let Some(drop_sql) = rebuild else {
                return Err(StoreError::NewerVersion { found, supported });
            };
            warn!(
                found,
                supported, "pre-release known destinations database, rebuilding its table"
            );
            db(conn.execute_batch(drop_sql))?;
        }
        db(conn.execute_batch(schema))?;
        db(conn.execute_batch(&format!("PRAGMA user_version = {supported}")))
    });
    match result {
        Ok(()) => db(conn.execute_batch("COMMIT"))?,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }
    Ok(conn)
}

/// Runs `f` inside BEGIN/COMMIT, rolling back on any error.
fn with_txn<T>(
    conn: &Connection,
    f: impl FnOnce(&Connection) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    db(conn.execute_batch("BEGIN"))?;
    match f(conn).and_then(|v| db(conn.execute_batch("COMMIT")).map(|()| v)) {
        Ok(v) => Ok(v),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

fn run_all<T>(
    conn: &Connection,
    sql: &str,
    rows: &[T],
    bind: &impl Fn(&mut Statement<'_>, &T) -> rusqlite::Result<usize>,
) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare(sql)?;
    let mut total = 0;
    for row in rows {
        total += bind(&mut stmt, row)?;
    }
    Ok(total)
}

/// Writes `rows` in chunks under savepoints, as `KnownDestinationsStore.__wrap_exec`:
/// a chunk that hits a constraint or data error is redone row by row, and each row
/// that still fails is rejected. Returns rows attempted minus rows rejected.
fn write_chunked<T>(
    conn: &Connection,
    sql: &str,
    table: RejectedTable,
    rows: &[T],
    key: impl Fn(&T) -> DestHash,
    bind: impl Fn(&mut Statement<'_>, &T) -> rusqlite::Result<usize>,
) -> Result<(usize, Vec<Rejection>), StoreError> {
    let mut rejected = Vec::new();
    for chunk in rows.chunks(CHUNK_ROWS) {
        db(conn.execute_batch("SAVEPOINT chunk"))?;
        match run_all(conn, sql, chunk, &bind) {
            Ok(_) => db(conn.execute_batch("RELEASE chunk"))?,
            Err(e) if is_row_error(&e) => {
                db(conn.execute_batch("ROLLBACK TO chunk"))?;
                for row in chunk {
                    db(conn.execute_batch("SAVEPOINT row"))?;
                    match run_all(conn, sql, std::slice::from_ref(row), &bind) {
                        Ok(_) => db(conn.execute_batch("RELEASE row"))?,
                        Err(e) if is_row_error(&e) => {
                            db(conn.execute_batch("ROLLBACK TO row"))?;
                            db(conn.execute_batch("RELEASE row"))?;
                            rejected.push(Rejection {
                                destination_hash: key(row),
                                table,
                                reason: e.to_string(),
                            });
                        }
                        Err(e) => return db(Err(e)),
                    }
                }
                db(conn.execute_batch("RELEASE chunk"))?;
            }
            Err(e) => return db(Err(e)),
        }
    }
    Ok((rows.len() - rejected.len(), rejected))
}

/// The side-table columns of a joined row; any that is missing or malformed reads as unknown.
fn decode_facts(row: &rusqlite::Row<'_>) -> Option<AnnounceFacts> {
    let hops: Option<i64> = row.get(9).ok()?;
    let name_hash: Option<Vec<u8>> = row.get(10).ok()?;
    let path_response: Option<i64> = row.get(11).ok()?;
    Some(AnnounceFacts::new(
        u8::try_from(hops?).ok()?,
        name_hash?.try_into().ok()?,
        path_response? != 0,
    ))
}

fn decode_known(row: &rusqlite::Row<'_>) -> Result<KnownDestinationRow, StoreError> {
    const T: &str = "known_destinations";
    let destination_hash = fixed::<16>(db(row.get(0))?, T)?;
    let last_heard: f64 = db(row.get(1))?;
    let packet_hash: Option<Vec<u8>> = db(row.get(2))?;
    let public_key = fixed::<64>(db(row.get(3))?, T)?;
    let app_data: Option<Vec<u8>> = db(row.get(4))?;
    let used: f64 = db(row.get(5))?;
    let stamp: Option<Vec<u8>> = db(row.get(6))?;
    let stamp_value: Option<f64> = db(row.get(7))?;
    let lr_cost: Option<f64> = db(row.get(8))?;
    Ok(KnownDestinationRow {
        destination_hash,
        last_heard,
        packet_hash: packet_hash.map(|h| fixed::<32>(h, T)).transpose()?,
        public_key,
        app_data,
        used,
        stamp,
        stamp_value: stamp_value.unwrap_or(0.0),
        lr_cost,
        announce_facts: None,
    })
}

/// Known destinations and received ratchets in `known_destinations.db`.
#[derive(Debug)]
pub struct SqliteKnownDestinations {
    conn: Connection,
    read_only: bool,
}

impl SqliteKnownDestinations {
    /// Opens or creates the file for reading and writing. A file from a pre-release
    /// build (`user_version` above 0) has its `known_destinations` table rebuilt empty.
    pub fn open_rw(path: &Path) -> Result<Self, StoreError> {
        let conn = open_rw_checked(
            path,
            KNOWN_DESTINATIONS_USER_VERSION,
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA journal_size_limit=8388608;",
            KD_SCHEMA,
            Some("DROP TABLE IF EXISTS known_destinations"),
        )?;
        // Side rows whose destination upstream deleted or replaced meanwhile.
        db(conn.execute(FACTS_PRUNE_SQL, []))?;
        Ok(Self {
            conn,
            read_only: false,
        })
    }

    /// Opens an existing file read-only. Nothing is created or altered.
    pub fn open_ro(path: &Path) -> Result<Self, StoreError> {
        let uri = format!("file:{}?mode=ro", uri_path(path)?);
        let conn = with_busy_timeout(db(Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?)?;
        Ok(Self {
            conn,
            read_only: true,
        })
    }
}

impl KnownDestinationStore for SqliteKnownDestinations {
    fn load_all(&mut self, f: &mut dyn FnMut(KnownDestinationRow)) -> Result<(), StoreError> {
        // A file upstream created has no side table.
        let has_facts: bool = db(self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='rs_announce_facts')",
            [],
            |r| r.get(0),
        ))?;
        let mut stmt = db(self.conn.prepare(if has_facts {
            KD_SELECT_WITH_FACTS_SQL
        } else {
            KD_SELECT_SQL
        }))?;
        let mut rows = db(stmt.query([]))?;
        let mut skipped = 0usize;
        while let Some(row) = db(rows.next())? {
            match decode_known(row) {
                Ok(mut decoded) => {
                    if has_facts {
                        decoded.announce_facts = decode_facts(row);
                    }
                    f(decoded)
                }
                Err(_) => skipped += 1,
            }
        }
        if skipped > 0 {
            warn!(skipped, "skipped undecodable known destination rows");
        }
        Ok(())
    }

    fn apply(
        &mut self,
        batch: &KdBatch,
        is_known: &dyn Fn(&DestHash) -> bool,
    ) -> Result<ApplyReport, StoreError> {
        if self.read_only {
            return Err(StoreError::ReadOnly);
        }
        if batch.is_empty() {
            return Ok(ApplyReport::default());
        }

        let kd_deletes: Vec<DestHash> = batch
            .deletes
            .iter()
            .copied()
            .filter(|h| !is_known(h))
            .collect();
        let ratchet_upserts: Vec<RatchetRow> = batch
            .ratchet_upserts
            .iter()
            .copied()
            .filter(|r| is_known(&r.destination_hash))
            .collect();
        let mut ratchet_deletes: Vec<DestHash> = batch
            .ratchet_upserts
            .iter()
            .map(|r| r.destination_hash)
            .filter(|h| !is_known(h))
            .collect();
        ratchet_deletes.extend(
            batch
                .ratchet_deletes
                .iter()
                .copied()
                .filter(|h| !is_known(h)),
        );

        with_txn(&self.conn, |conn| {
            let (kd_written, mut rejected) = write_chunked(
                conn,
                KD_UPSERT_SQL,
                RejectedTable::KnownDestination,
                &batch.upserts,
                |r| r.destination_hash,
                |s, r| {
                    let ident = identity_hash(&r.public_key);
                    s.execute(params![
                        r.destination_hash.as_slice(),
                        r.last_heard,
                        r.packet_hash.as_ref().map(|h| h.as_slice()),
                        r.public_key.as_slice(),
                        r.app_data.as_deref(),
                        r.used,
                        r.stamp.as_deref(),
                        r.stamp_value,
                        r.lr_cost,
                        ident.as_slice(),
                    ])
                },
            )?;
            // The side row goes in the row's own transaction, and goes with it.
            {
                let refused: HashSet<DestHash> =
                    rejected.iter().map(|r| r.destination_hash).collect();
                let mut upsert = db(conn.prepare(FACTS_UPSERT_SQL))?;
                let mut delete = db(conn.prepare(FACTS_DELETE_SQL))?;
                for r in &batch.upserts {
                    match r.announce_facts {
                        Some(facts) if !refused.contains(&r.destination_hash) => {
                            db(upsert.execute(params![
                                r.destination_hash.as_slice(),
                                r.last_heard,
                                facts.hops,
                                facts.name_hash.as_slice(),
                                facts.path_response,
                            ]))?;
                        }
                        _ => {
                            db(delete.execute(params![r.destination_hash.as_slice()]))?;
                        }
                    }
                }
                for h in &kd_deletes {
                    db(delete.execute(params![h.as_slice()]))?;
                }
            }
            let (kd_deleted, kd_rej) = write_chunked(
                conn,
                KD_DELETE_SQL,
                RejectedTable::KnownDestination,
                &kd_deletes,
                |h| *h,
                |s, h| s.execute(params![h.as_slice()]),
            )?;
            let (r_written, r_rej) = write_chunked(
                conn,
                RATCHET_UPSERT_SQL,
                RejectedTable::Ratchet,
                &ratchet_upserts,
                |r| r.destination_hash,
                |s, r| {
                    s.execute(params![
                        r.destination_hash.as_slice(),
                        r.ratchet.as_slice(),
                        r.received
                    ])
                },
            )?;
            let (r_deleted, r_del_rej) = write_chunked(
                conn,
                RATCHET_DELETE_SQL,
                RejectedTable::Ratchet,
                &ratchet_deletes,
                |h| *h,
                |s, h| s.execute(params![h.as_slice()]),
            )?;
            rejected.extend(kd_rej);
            rejected.extend(r_rej);
            rejected.extend(r_del_rej);
            Ok(ApplyReport {
                written: kd_written + kd_deleted + r_written + r_deleted,
                rejected,
            })
        })
    }

    fn fetch_ratchet(
        &mut self,
        destination: &DestHash,
    ) -> Result<Option<(Ratchet, f64)>, StoreError> {
        let row = db(self
            .conn
            .query_row(
                "SELECT ratchet, received FROM ratchets WHERE destination_hash=?1",
                params![destination.as_slice()],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, f64>(1)?)),
            )
            .optional())?;
        row.map(|(ratchet, received)| Ok((fixed::<32>(ratchet, "ratchets")?, received)))
            .transpose()
    }

    fn expire_ratchets(&mut self, cutoff: f64) -> Result<Vec<DestHash>, StoreError> {
        if self.read_only {
            return Err(StoreError::ReadOnly);
        }
        let expired: Vec<DestHash> = {
            let mut stmt = db(self
                .conn
                .prepare("SELECT destination_hash FROM ratchets WHERE received<?1"))?;
            let rows = db(stmt.query_map(params![cutoff], |r| r.get::<_, Vec<u8>>(0)))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(fixed::<16>(db(row)?, "ratchets")?);
            }
            out
        };
        if expired.is_empty() {
            return Ok(expired);
        }
        with_txn(&self.conn, |conn| {
            let mut stmt = db(conn.prepare(RATCHET_DELETE_SQL))?;
            for hash in &expired {
                db(stmt.execute(params![hash.as_slice()]))?;
            }
            Ok(())
        })?;
        Ok(expired)
    }
}

/// The announce cache in `announces.db`.
#[derive(Debug)]
pub struct SqliteAnnounceCache {
    conn: Connection,
}

impl SqliteAnnounceCache {
    /// Opens or creates the file for reading and writing. A file whose `user_version`
    /// is newer than this crate knows is refused and not modified.
    pub fn open_rw(path: &Path) -> Result<Self, StoreError> {
        let conn = open_rw_checked(
            path,
            ANNOUNCE_CACHE_USER_VERSION,
            "PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA journal_size_limit=8388608;",
            ANNOUNCE_SCHEMA,
            None,
        )?;
        Ok(Self { conn })
    }

    /// Opens an existing file read-only, for [`AnnounceCacheStore::fetch`]. The
    /// database is not created or altered.
    pub fn open_ro(path: &Path) -> Result<Self, StoreError> {
        let uri = format!("file:{}?mode=ro", uri_path(path)?);
        let conn = with_busy_timeout(db(Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?)?;
        Ok(Self { conn })
    }
}

impl AnnounceCacheStore for SqliteAnnounceCache {
    fn upsert(&mut self, rows: &[AnnounceRow]) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        with_txn(&self.conn, |conn| {
            for chunk in rows.chunks(CHUNK_ROWS) {
                let mut stmt = db(conn.prepare(ANNOUNCE_UPSERT_SQL))?;
                for r in chunk {
                    db(stmt.execute(params![
                        r.packet_hash.as_slice(),
                        r.received,
                        r.raw.as_slice(),
                        r.interface_reference.as_deref(),
                    ]))?;
                }
            }
            Ok(())
        })
    }

    fn fetch(&mut self, packet_hash: &PacketHash) -> Result<Option<CachedAnnounce>, StoreError> {
        db(self
            .conn
            .query_row(
                "SELECT raw, interface_reference FROM cached_announces WHERE packet_hash=?1",
                params![packet_hash.as_slice()],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .optional())
    }

    fn retain_only(&mut self, keep: &HashSet<PacketHash>) -> Result<usize, StoreError> {
        let keep: Vec<&PacketHash> = keep.iter().collect();
        let removed = with_txn(&self.conn, |conn| {
            db(conn.execute_batch(
                "DROP TABLE IF EXISTS temp.active_announces; CREATE TEMP TABLE active_announces (packet_hash BLOB PRIMARY KEY);",
            ))?;
            for chunk in keep.chunks(CHUNK_ROWS) {
                let mut stmt =
                    db(conn.prepare("INSERT OR IGNORE INTO active_announces VALUES (?1)"))?;
                for h in chunk {
                    db(stmt.execute(params![h.as_slice()]))?;
                }
            }
            db(conn.execute(
                "DELETE FROM cached_announces WHERE packet_hash NOT IN (SELECT packet_hash FROM active_announces)",
                [],
            ))
        })?;
        if removed > 0 {
            db(self.conn.execute_batch("PRAGMA incremental_vacuum"))?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rns-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("db.sqlite")
    }

    fn row(h: u8) -> KnownDestinationRow {
        KnownDestinationRow::new([h; 16], 100.0, [h; 64])
    }

    #[test]
    fn newer_announce_cache_version_is_refused_and_file_unchanged() {
        let path = temp_db("newer-announce");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA user_version = 7; CREATE TABLE cached_announces (x);")
                .unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            SqliteAnnounceCache::open_rw(&path),
            Err(StoreError::NewerVersion {
                found: 7,
                supported: 1
            })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn newer_known_destinations_version_is_rebuilt_keeping_ratchets() {
        let path = temp_db("newer-kd");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA user_version = 7; CREATE TABLE known_destinations (x); CREATE TABLE ratchets (destination_hash BLOB PRIMARY KEY, ratchet BLOB NOT NULL, received REAL NOT NULL); INSERT INTO ratchets VALUES (x'01', x'02', 3.0);",
            )
            .unwrap();
        }
        let mut store = SqliteKnownDestinations::open_rw(&path).unwrap();
        let mut rows = Vec::new();
        store.load_all(&mut |r| rows.push(r)).unwrap();
        assert!(rows.is_empty());
        let version: i64 = Connection::open(&path)
            .unwrap()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, KNOWN_DESTINATIONS_USER_VERSION);
        let kept: i64 = Connection::open(&path)
            .unwrap()
            .query_row("SELECT count(*) FROM ratchets", [], |r| r.get(0))
            .unwrap();
        assert_eq!(kept, 1);
    }

    #[test]
    fn connections_wait_five_seconds_on_locked_files() {
        let path = temp_db("busy");
        let kd = SqliteKnownDestinations::open_rw(&path).unwrap();
        let ro = SqliteKnownDestinations::open_ro(&path).unwrap();
        let cache = SqliteAnnounceCache::open_rw(&temp_db("busy-announce")).unwrap();
        for conn in [&kd.conn, &ro.conn, &cache.conn] {
            let ms: i64 = conn
                .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
                .unwrap();
            assert_eq!(ms, 5000);
        }
    }

    #[test]
    fn busy_and_locked_codes_map_to_locked() {
        for code in [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED] {
            let err = rusqlite::ffi::Error::new(code);
            let failure = rusqlite::Error::SqliteFailure(err, None);
            assert!(matches!(db::<()>(Err(failure)), Err(StoreError::Locked)));
        }
    }

    #[test]
    fn ratchet_for_unknown_destination_is_deleted_and_known_one_is_kept() {
        let path = temp_db("ratchet");
        let mut store = SqliteKnownDestinations::open_rw(&path).unwrap();
        let batch = KdBatch {
            upserts: vec![row(1)],
            ratchet_upserts: vec![
                RatchetRow::new([1; 16], [7; 32], 50.0),
                RatchetRow::new([2; 16], [8; 32], 50.0),
            ],
            ..KdBatch::default()
        };
        let report = store.apply(&batch, &|h| *h == [1; 16]).unwrap();
        assert!(report.rejected.is_empty());
        assert_eq!(
            store.fetch_ratchet(&[1; 16]).unwrap(),
            Some(([7; 32], 50.0))
        );
        assert_eq!(store.fetch_ratchet(&[2; 16]).unwrap(), None);
    }

    #[test]
    fn row_failing_a_constraint_is_rejected_and_the_rest_is_written() {
        let path = temp_db("reject");
        let mut store = SqliteKnownDestinations::open_rw(&path).unwrap();
        // SQLite binds NaN as NULL, which fails `last_heard NOT NULL`.
        let mut bad = row(2);
        bad.last_heard = f64::NAN;
        let batch = KdBatch {
            upserts: vec![row(1), bad],
            ..KdBatch::default()
        };
        let report = store.apply(&batch, &|_| true).unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].destination_hash, [2; 16]);
        assert_eq!(report.rejected[0].table, RejectedTable::KnownDestination);
        let mut seen = Vec::new();
        store
            .load_all(&mut |r| seen.push(r.destination_hash))
            .unwrap();
        assert_eq!(seen, vec![[1; 16]]);
    }

    #[test]
    fn read_only_store_loads_rows_and_refuses_writes() {
        let path = temp_db("ro");
        {
            let mut rw = SqliteKnownDestinations::open_rw(&path).unwrap();
            let batch = KdBatch {
                upserts: vec![row(9)],
                ..KdBatch::default()
            };
            rw.apply(&batch, &|_| true).unwrap();
        }
        let mut ro = SqliteKnownDestinations::open_ro(&path).unwrap();
        let mut seen = Vec::new();
        ro.load_all(&mut |r| seen.push(r.destination_hash)).unwrap();
        assert_eq!(seen, vec![[9; 16]]);
        assert!(matches!(
            ro.apply(&KdBatch::default(), &|_| true),
            Err(StoreError::ReadOnly)
        ));
    }

    #[test]
    fn announce_retain_only_removes_rows_outside_keep_set() {
        let path = temp_db("announce");
        let mut cache = SqliteAnnounceCache::open_rw(&path).unwrap();
        cache
            .upsert(&[
                AnnounceRow::new([1; 32], 1.0, vec![1], Some("tcp".into())),
                AnnounceRow::new([2; 32], 1.0, vec![2], None),
            ])
            .unwrap();
        let keep: HashSet<PacketHash> = [[1; 32]].into_iter().collect();
        assert_eq!(cache.retain_only(&keep).unwrap(), 1);
        assert_eq!(cache.fetch(&[2; 32]).unwrap(), None);
        assert_eq!(
            cache.fetch(&[1; 32]).unwrap(),
            Some((vec![1], Some("tcp".into())))
        );
    }
}
