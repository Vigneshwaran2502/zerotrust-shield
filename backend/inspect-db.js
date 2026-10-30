const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.sqlite');

db.all(
  "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
  (err, rows) => {
    if (err) {
      console.error(err.message);
    } else {
      for (const row of rows) {
        console.log('\n' + row.name + '\n' + row.sql);
      }
    }
    db.close();
  }
);
