import { openDb, migrate, defaultDbPath } from './db.js';

const db = openDb(defaultDbPath());
migrate(db);
console.log(`Migrated database at ${defaultDbPath()}`);
db.close();
