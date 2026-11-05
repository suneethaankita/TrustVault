const { initDb } = require('../database');

console.log('Seeding TrustVault database with evaluation accounts and records...');
initDb()
  .then(() => {
    console.log('Database successfully initialized and seeded.');
    process.exit(0);
  })
  .catch((err) => {
    console.error('Database seeding failed:', err);
    process.exit(1);
  });
