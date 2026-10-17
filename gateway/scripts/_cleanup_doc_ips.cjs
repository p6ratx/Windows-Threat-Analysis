const Database = require('better-sqlite3');
const path = require('path');
const db = new Database(path.join(__dirname, '../../data/aegis.db'));

const peers = db
  .prepare(
    `DELETE FROM remote_peers
     WHERE remote_ip LIKE '203.0.113.%'
        OR remote_ip LIKE '198.51.100.%'
        OR remote_ip LIKE '192.0.2.%'
        OR process_name = 'test.exe'`
  )
  .run();

const attrs = db
  .prepare(
    `DELETE FROM attribution_records
     WHERE subject_id LIKE 'ip:203.0.113.%'
        OR subject_id LIKE 'ip:198.51.100.%'
        OR subject_id LIKE 'ip:192.0.2.%'
        OR subject_label = 'test.exe'`
  )
  .run();

console.log({ peers: peers.changes, attrs: attrs.changes });
db.close();
