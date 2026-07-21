import { parseMigrationEnvironment } from "@mergesignal/config";

import { migrateDatabase } from "./migrations.js";

const environment = parseMigrationEnvironment();
await migrateDatabase(environment.DATABASE_URL);
process.stdout.write("MergeSignal database migrations are current.\n");
