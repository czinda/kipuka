//! Database access layer.
//!
//! Provides connection pool initialization, migration execution, and
//! query helpers for the three supported backends: SQLite, PostgreSQL,
//! and MariaDB.
//!
//! The shared connection pool type [`Db`] is a runtime-dispatch `AnyPool`
//! that routes queries to the configured backend.  All write transactions
//! on SQLite should go through [`begin_write`] rather than `pool.begin()`
//! to avoid `SQLITE_BUSY_SNAPSHOT` in WAL mode.

pub mod schema;

use crate::config::DbConfig;
use crate::error::KipukaError;

/// Type alias for the shared connection pool (runtime-dispatch Any backend).
pub type Db = sqlx::AnyPool;

/// Which database backend is active.
///
/// Drives `begin_write` only: SQLite requires `BEGIN IMMEDIATE` to prevent
/// `SQLITE_BUSY_SNAPSHOT` (error 517) in WAL mode; PostgreSQL and MariaDB use
/// standard MVCC and need only `BEGIN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbKind {
    Sqlite,
    Postgres,
    MariaDb,
}

impl DbKind {
    /// Infer the backend from the connection URL scheme.
    pub fn from_url(url: &str) -> Self {
        if url.starts_with("postgres") {
            DbKind::Postgres
        } else if url.starts_with("mariadb") || url.starts_with("mysql") {
            DbKind::MariaDb
        } else {
            DbKind::Sqlite
        }
    }
}

/// Global PostgreSQL flag for parameter rewriting.
///
/// sqlx 0.8's `AnyPool` does not reliably rewrite `?` parameter placeholders
/// to `$N` for PostgreSQL.  Call [`pg_sql`] on every SQL string that contains
/// `?` before passing it to sqlx.
static IS_POSTGRES: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Rewrite `?` → `$1`, `$2`, … for PostgreSQL; return unchanged for others.
///
/// The rewritten string is cached permanently (via `Box::leak`) keyed by the
/// pointer identity of the static string literal, so each unique query string
/// is rewritten at most once.
#[allow(dead_code)]
pub fn pg_sql(s: &'static str) -> &'static str {
    if !IS_POSTGRES.get().copied().unwrap_or(false) {
        return s;
    }
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<usize, &'static str>>,
    > = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let key = s.as_ptr() as usize;
    {
        let guard = cache.lock().unwrap();
        if let Some(&cached) = guard.get(&key) {
            return cached;
        }
    }
    // Slow path: rewrite then store for the lifetime of the process.
    let mut result = String::with_capacity(s.len() + 16);
    let mut param_num = 0u32;
    for ch in s.chars() {
        if ch == '?' {
            param_num += 1;
            result.push('$');
            result.push_str(&param_num.to_string());
        } else {
            result.push(ch);
        }
    }
    let leaked: &'static str = Box::leak(result.into_boxed_str());
    cache.lock().unwrap().insert(key, leaked);
    leaked
}

/// Rewrite `?` → `$1`, `$2`, … for PostgreSQL on a dynamically-built SQL
/// string.  Unlike [`pg_sql`], which operates on `&'static str` literals,
/// this accepts an owned `String` and returns an owned `String`.
///
/// When the backend is not PostgreSQL the input is returned unchanged.
#[allow(dead_code)]
pub(crate) fn pg_sql_dynamic(s: String) -> String {
    if !IS_POSTGRES.get().copied().unwrap_or(false) {
        return s;
    }
    let mut result = String::with_capacity(s.len() + 16);
    let mut param_num = 0u32;
    for ch in s.chars() {
        if ch == '?' {
            param_num += 1;
            result.push('$');
            result.push_str(&param_num.to_string());
        } else {
            result.push(ch);
        }
    }
    result
}

/// Initialize the primary (read-write) database connection pool.
///
/// The `resolved_url` is the pre-resolved database URL from [`SecretResolver`].
pub async fn init_pool(config: &DbConfig, resolved_url: &str) -> Result<(Db, DbKind), KipukaError> {
    let url = resolved_url.to_string();

    let kind = DbKind::from_url(&url);
    let _ = IS_POSTGRES.set(kind == DbKind::Postgres);

    let pool_opts = sqlx::any::AnyPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(config.connect_timeout_secs))
        .max_lifetime(std::time::Duration::from_secs(config.max_lifetime_secs));

    let pool_opts = if let Some(max) = config.max_connections {
        pool_opts.max_connections(max)
    } else {
        match kind {
            DbKind::Sqlite => pool_opts.max_connections(1),
            _ => pool_opts.max_connections(10),
        }
    };

    let pool_opts = if let Some(min) = config.min_connections {
        pool_opts.min_connections(min)
    } else {
        pool_opts
    };

    let pool = pool_opts
        .connect(&url)
        .await
        .map_err(|e| KipukaError::Db(format!("failed to connect to database: {e}")))?;

    // Enable WAL mode for SQLite
    if kind == DbKind::Sqlite && config.sqlite_wal {
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&pool)
            .await
            .map_err(|e| KipukaError::Db(format!("failed to enable WAL mode: {e}")))?;
    }

    Ok((pool, kind))
}

/// Initialize a read-only connection pool for GET handlers.
///
/// For SQLite file-backed databases, this opens a `?mode=ro` pool that
/// never acquires the write lock, enabling concurrent reads during writes
/// (WAL concurrency benefit).  For `:memory:` and non-SQLite backends,
/// returns a clone of the primary pool.
pub async fn init_ro_pool(
    _config: &DbConfig,
    kind: DbKind,
    resolved_url: &str,
) -> Result<Db, KipukaError> {
    let url = resolved_url.to_string();

    // Only SQLite file-backed databases benefit from a separate RO pool
    if kind != DbKind::Sqlite || url.contains(":memory:") {
        // For non-SQLite or in-memory: caller should clone the primary pool
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .map_err(|e| KipukaError::Db(format!("failed to connect RO pool: {e}")))?;
        return Ok(pool);
    }

    // Build a read-only URL for SQLite
    let ro_url = if url.contains('?') {
        format!("{url}&mode=ro")
    } else {
        format!("{url}?mode=ro")
    };

    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(4)
        .connect(&ro_url)
        .await
        .map_err(|e| KipukaError::Db(format!("failed to connect RO pool: {e}")))?;

    Ok(pool)
}

/// Begin a write transaction.
///
/// SQLite uses `BEGIN IMMEDIATE` to avoid `SQLITE_BUSY_SNAPSHOT` under WAL
/// mode; other backends use standard `BEGIN`.
pub async fn begin_write(
    pool: &Db,
    kind: DbKind,
) -> Result<sqlx::Transaction<'_, sqlx::Any>, KipukaError> {
    if kind == DbKind::Sqlite {
        // SQLite: BEGIN IMMEDIATE prevents SQLITE_BUSY_SNAPSHOT
        sqlx::query("BEGIN IMMEDIATE")
            .execute(pool)
            .await
            .map_err(|e| KipukaError::Db(format!("BEGIN IMMEDIATE failed: {e}")))?;
    }
    let tx = pool
        .begin()
        .await
        .map_err(|e| KipukaError::Db(format!("begin transaction failed: {e}")))?;
    Ok(tx)
}

/// Run pending database migrations.
pub async fn run_migrations(pool: &Db, kind: DbKind) -> Result<(), KipukaError> {
    crate::db::schema::run_migrations(pool, kind).await
}
