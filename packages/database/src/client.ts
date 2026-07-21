import { Kysely, PostgresDialect, sql, type Transaction } from "kysely";
import pg from "pg";

import type { MergeSignalDatabase } from "./types.js";

const { Pool } = pg;

export interface DatabaseOptions {
  applicationName: string;
  maximumPoolSize?: number;
}

export type Database = Kysely<MergeSignalDatabase>;
export type TenantTransaction = Transaction<MergeSignalDatabase>;

export function createDatabase(connectionString: string, options: DatabaseOptions): Database {
  const poolOptions: pg.PoolConfig = {
    application_name: options.applicationName,
    connectionString,
    max: options.maximumPoolSize ?? 10
  };

  return new Kysely<MergeSignalDatabase>({
    dialect: new PostgresDialect({ pool: new Pool(poolOptions) })
  });
}

export async function withTenantTransaction<T>(
  database: Database,
  tenantId: string,
  operation: (transaction: TenantTransaction) => Promise<T>
): Promise<T> {
  return database.transaction().execute(async (transaction) => {
    await sql`select set_config('app.tenant_id', ${tenantId}, true)`.execute(transaction);
    return operation(transaction);
  });
}

function isRetryableTransactionError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error.code === "40001" || error.code === "40P01")
  );
}

export async function withTenantSerializableTransaction<T>(
  database: Database,
  tenantId: string,
  operation: (transaction: TenantTransaction) => Promise<T>,
  maximumAttempts = 5
): Promise<T> {
  for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
    try {
      return await database
        .transaction()
        .setIsolationLevel("serializable")
        .execute(async (transaction) => {
          await sql`select set_config('app.tenant_id', ${tenantId}, true)`.execute(transaction);
          return operation(transaction);
        });
    } catch (error) {
      if (!isRetryableTransactionError(error) || attempt === maximumAttempts) throw error;
    }
  }
  throw new Error("Serializable transaction retry loop exhausted");
}
