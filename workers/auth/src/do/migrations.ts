/**
 * Numbered schema migrations for SQLite-backed Durable Objects. Run from the
 * DO constructor inside `ctx.blockConcurrencyWhile`. Migration N is the
 * N-th entry (1-based); applied ids are tracked in `_migrations`.
 * Never edit or reorder a shipped migration; append a new one.
 */

export type Migration = string | ((sql: SqlStorage) => void);

export type MigrationStorage = Pick<DurableObjectStorage, 'sql' | 'transactionSync'>;

/** Apply every migration not yet recorded. Returns the ids applied. */
export function runMigrations(storage: MigrationStorage, migrations: readonly Migration[]): number[] {
  const { sql } = storage;
  sql.exec(
    'CREATE TABLE IF NOT EXISTS _migrations (id INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)',
  );
  const row = sql.exec<{ v: number | null }>('SELECT MAX(id) AS v FROM _migrations').one();
  const current = row.v ?? 0;
  const applied: number[] = [];
  for (let id = current + 1; id <= migrations.length; id++) {
    const migration = migrations[id - 1]!;
    storage.transactionSync(() => {
      if (typeof migration === 'string') sql.exec(migration);
      else migration(sql);
      sql.exec('INSERT INTO _migrations (id, applied_at) VALUES (?, ?)', id, Date.now());
    });
    applied.push(id);
  }
  return applied;
}
