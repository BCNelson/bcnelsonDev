/**
 * A minimal stand-in for DurableObjectState backed by Node's built-in
 * SQLite, enough to exercise the DO SQL in plain vitest. It mimics
 * ctx.storage.sql.exec (cursor with toArray/one/rowsWritten),
 * transactionSync, alarms and blockConcurrencyWhile. It is not workerd:
 * input/output gates and RPC serialization are not modelled.
 */

interface NodeStatement {
  all(...params: unknown[]): Record<string, unknown>[];
  run(...params: unknown[]): { changes: number | bigint };
  readonly columns?: () => unknown[];
}
interface NodeDatabase {
  exec(sql: string): void;
  prepare(sql: string): NodeStatement;
}

// Imported by string so tsc (no @types/node) doesn't try to resolve it.
const sqliteModule = 'node:sqlite';
const { DatabaseSync } = (await import(sqliteModule)) as {
  DatabaseSync: new (path: string) => NodeDatabase;
};

/** Split on `;` outside quotes; good enough for our schema strings. */
function splitStatements(query: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: string | null = null;
  for (const ch of query) {
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === ';') {
      if (cur.trim()) out.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

class FakeCursor {
  constructor(private rows: Record<string, unknown>[], readonly rowsWritten: number) {}
  toArray() { return this.rows; }
  one() {
    if (this.rows.length !== 1) throw new Error(`Expected exactly one row, got ${this.rows.length}`);
    return this.rows[0]!;
  }
  [Symbol.iterator]() { return this.rows[Symbol.iterator](); }
}

export function fakeState() {
  const db = new DatabaseSync(':memory:');
  let depth = 0;
  let alarm: number | null = null;
  const sql = {
    exec(query: string, ...bindings: unknown[]) {
      const statements = splitStatements(query);
      let rows: Record<string, unknown>[] = [];
      let written = 0;
      for (const [i, text] of statements.entries()) {
        const stmt = db.prepare(text);
        const params = i === statements.length - 1 ? bindings : [];
        if (/^\s*(SELECT|WITH|PRAGMA)/i.test(text)) {
          rows = stmt.all(...params).map((r) => ({ ...r }));
        } else {
          written += Number(stmt.run(...params).changes);
          rows = [];
        }
      }
      return new FakeCursor(rows, written);
    },
    get databaseSize() { return 0; },
  };
  const storage = {
    sql,
    transactionSync<T>(fn: () => T): T {
      const name = `sp${depth++}`;
      db.exec(`SAVEPOINT ${name}`);
      try {
        const result = fn();
        db.exec(`RELEASE ${name}`);
        return result;
      } catch (err) {
        db.exec(`ROLLBACK TO ${name}`);
        db.exec(`RELEASE ${name}`);
        throw err;
      } finally {
        depth--;
      }
    },
    async getAlarm() { return alarm; },
    async setAlarm(at: number | Date) { alarm = typeof at === 'number' ? at : at.getTime(); },
    async deleteAlarm() { alarm = null; },
  };
  const state = {
    storage,
    id: { toString: () => 'fake', name: undefined },
    async blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T> { return fn(); },
    waitUntil() {},
  };
  return { state, db, getAlarm: () => alarm };
}

/** Stand-in for `cloudflare:workers`' DurableObject base class. */
export class FakeDurableObject {
  protected ctx: unknown;
  protected env: unknown;
  constructor(ctx: unknown, env: unknown) {
    this.ctx = ctx;
    this.env = env;
  }
}
