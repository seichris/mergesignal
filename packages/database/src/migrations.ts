import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import pg from "pg";

const { Pool } = pg;
const migrationDirectory = fileURLToPath(new URL("../migrations/", import.meta.url));

export async function migrateDatabase(connectionString: string): Promise<void> {
  const pool = new Pool({
    application_name: "mergesignal-migration",
    connectionString,
    max: 1
  });
  const client = await pool.connect();

  try {
    await client.query("select pg_advisory_lock(hashtext('mergesignal:migrations'))");
    await client.query(`
      create table if not exists public.mergesignal_schema_migrations (
        name text primary key,
        sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
        applied_at timestamptz not null default clock_timestamp()
      )
    `);

    const filenames = (await readdir(migrationDirectory))
      .filter((name) => /^\d{4}_[a-z0-9_]+\.sql$/.test(name))
      .sort();

    for (const filename of filenames) {
      const bytes = await readFile(new URL(`../migrations/${filename}`, import.meta.url));
      const digest = createHash("sha256").update(bytes).digest("hex");
      const existing = await client.query<{ sha256: string }>(
        "select sha256 from public.mergesignal_schema_migrations where name = $1",
        [filename]
      );
      if (existing.rows[0] !== undefined) {
        if (existing.rows[0].sha256 !== digest) {
          throw new Error(`Applied migration was modified: ${filename}`);
        }
        continue;
      }

      await client.query("begin");
      try {
        await client.query(bytes.toString("utf8"));
        await client.query(
          "insert into public.mergesignal_schema_migrations (name, sha256) values ($1, $2)",
          [filename, digest]
        );
        await client.query("commit");
      } catch (error) {
        await client.query("rollback");
        throw error;
      }
    }
  } finally {
    await client.query("select pg_advisory_unlock(hashtext('mergesignal:migrations'))").catch(() => undefined);
    client.release();
    await pool.end();
  }
}
