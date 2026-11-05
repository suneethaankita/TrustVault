const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { encryptBuffer } = require('./utils/cryptoVault');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'trustvault.db');
const db = new sqlite3.Database(DB_PATH);

// Helper for running queries with Promises
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// Compute hash for tamper-evident audit logging
function computeEntryHash(prevHash, entry) {
  const actorEmail = entry.actor_email || '';
  const action = entry.action || '';
  const resourceType = entry.resource_type || '';
  const resourceId = entry.resource_id || '';
  const status = entry.status || '';
  const ipAddress = entry.ip_address || '';
  const details = entry.details || '';
  const content = `${prevHash}|${entry.timestamp}|${actorEmail}|${action}|${resourceType}|${resourceId}|${status}|${ipAddress}|${details}`;
  return crypto.createHash('sha256').update(content).digest('hex');
}

// Log audit event into database with cryptographic hash chaining
async function logAuditEvent({ actor_id, actor_name, actor_email, action, resource_type, resource_id, resource_name, status, ip_address, user_agent, details }) {
  try {
    const timestamp = new Date().toISOString();

    // Get latest log's entry_hash
    const lastLog = await get('SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1');
    const previous_hash = lastLog && lastLog.entry_hash ? lastLog.entry_hash : '0000000000000000000000000000000000000000000000000000000000000000';

    const finalActorEmail = actor_email || 'anonymous@trustvault.local';
    const finalActorName = actor_name || 'Anonymous';
    const finalResourceType = resource_type || 'SYSTEM';
    const finalResourceId = resource_id || null;
    const finalIp = ip_address || '127.0.0.1';
    const finalUserAgent = user_agent || 'unknown';
    const finalDetails = details || '';

    const entry_hash = computeEntryHash(previous_hash, {
      timestamp,
      actor_email: finalActorEmail,
      action,
      resource_type: finalResourceType,
      resource_id: finalResourceId,
      status,
      ip_address: finalIp,
      details: finalDetails
    });

    const result = await run(
      `INSERT INTO audit_logs (
        timestamp, actor_id, actor_name, actor_email, action,
        resource_type, resource_id, resource_name, status,
        ip_address, user_agent, details, previous_hash, entry_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        timestamp, actor_id || null, finalActorName, finalActorEmail,
        action, finalResourceType, finalResourceId, resource_name || null,
        status, finalIp, finalUserAgent, finalDetails,
        previous_hash, entry_hash
      ]
    );

    return result.lastID;
  } catch (err) {
    console.error('CRITICAL: Audit log failure:', err.message);
  }
}

// Initialize tables and default seed data
async function initDb() {
  // Ensure storage directories exist
  const storageDir = path.join(__dirname, 'storage', 'vault_files');
  if (!fs.existsSync(storageDir)) {
    fs.mkdirSync(storageDir, { recursive: true });
  }

  // 1. Users Table
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT CHECK(role IN ('ADMIN', 'OWNER', 'VIEWER')) NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  // 2. Documents Table
  await run(`
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      stored_filename TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      category TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // 3. Permissions Table (Direct per-document access grants)
  await run(`
    CREATE TABLE IF NOT EXISTS permissions (
      id TEXT PRIMARY KEY,
      document_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      permission_level TEXT CHECK(permission_level IN ('READ', 'EDIT')) NOT NULL,
      granted_by TEXT NOT NULL,
      granted_at TEXT NOT NULL,
      UNIQUE(document_id, user_id),
      FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (granted_by) REFERENCES users(id)
    )
  `);

  // 4. Audit Logs Table (Tamper-evident with previous_hash & entry_hash)
  await run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      actor_id TEXT,
      actor_name TEXT NOT NULL,
      actor_email TEXT NOT NULL,
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT,
      resource_name TEXT,
      status TEXT CHECK(status IN ('SUCCESS', 'DENIED')) NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      details TEXT,
      previous_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL
    )
  `);

  // Seed default accounts if not present
  const userCount = await get('SELECT COUNT(*) as count FROM users');
  if (userCount.count === 0) {
    console.log('[TrustVault] Seeding default accounts for evaluation...');

    const saltRounds = 10;
    const defaultPassword = 'Password123!';
    const passwordHash = await bcrypt.hash(defaultPassword, saltRounds);

    const now = new Date().toISOString();

    // 1. Admin account
    const adminId = crypto.randomUUID();
    await run(
      'INSERT INTO users (id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [adminId, 'Security Admin', 'admin@trustvault.com', passwordHash, 'ADMIN', now]
    );

    // 2. Document Owner account
    const ownerId = crypto.randomUUID();
    await run(
      'INSERT INTO users (id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [ownerId, 'Alice Document Owner', 'owner@trustvault.com', passwordHash, 'OWNER', now]
    );

    // 3. Document Viewer account
    const viewerId = crypto.randomUUID();
    await run(
      'INSERT INTO users (id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [viewerId, 'Bob Viewer', 'viewer@trustvault.com', passwordHash, 'VIEWER', now]
    );

    // 4. Secondary Viewer (to test that ungranted viewers are blocked)
    const outsiderId = crypto.randomUUID();
    await run(
      'INSERT INTO users (id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [outsiderId, 'Charlie Outsider', 'outsider@trustvault.com', passwordHash, 'VIEWER', now]
    );

    // Create a sample confidential file for Alice (Owner)
    const sampleDocId = crypto.randomUUID();
    const sampleFilename = `${crypto.randomUUID()}.txt`;
    const sampleFilePath = path.join(storageDir, sampleFilename);
    const sampleContent = `CONFIDENTIAL TRUSTVAULT RECORD\nDocument ID: ${sampleDocId}\nClassification: Strictly Restricted - Board & Authorized Personnel Only.\nSalary and Strategy Audit 2026.\nUnauthorized access is tracked and reported.`;

    // Encrypt at rest with AES-256-GCM before writing to disk
    fs.writeFileSync(sampleFilePath, encryptBuffer(Buffer.from(sampleContent, 'utf8')));

    await run(
      `INSERT INTO documents (id, title, original_filename, stored_filename, mime_type, file_size, category, owner_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        sampleDocId,
        'Executive Salary Letter 2026',
        'Executive_Salary_2026.txt',
        sampleFilename,
        'text/plain',
        Buffer.byteLength(sampleContent),
        'Financial',
        ownerId,
        now,
        now
      ]
    );

    // Grant Bob 'READ' permission
    const permId = crypto.randomUUID();
    await run(
      `INSERT INTO permissions (id, document_id, user_id, permission_level, granted_by, granted_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [permId, sampleDocId, viewerId, 'READ', ownerId, now]
    );

    // Initial Audit logs
    await logAuditEvent({
      actor_id: adminId,
      actor_name: 'Security Admin',
      actor_email: 'admin@trustvault.com',
      action: 'SYSTEM_GENESIS',
      resource_type: 'SYSTEM',
      status: 'SUCCESS',
      ip_address: '127.0.0.1',
      details: 'TrustVault database initialized with cryptographically verified seed data.'
    });

    await logAuditEvent({
      actor_id: ownerId,
      actor_name: 'Alice Document Owner',
      actor_email: 'owner@trustvault.com',
      action: 'DOCUMENT_UPLOAD',
      resource_type: 'DOCUMENT',
      resource_id: sampleDocId,
      resource_name: 'Executive Salary Letter 2026',
      status: 'SUCCESS',
      ip_address: '127.0.0.1',
      details: 'Initial confidential document uploaded.'
    });

    await logAuditEvent({
      actor_id: ownerId,
      actor_name: 'Alice Document Owner',
      actor_email: 'owner@trustvault.com',
      action: 'PERMISSION_GRANT',
      resource_type: 'PERMISSION',
      resource_id: sampleDocId,
      resource_name: 'Executive Salary Letter 2026',
      status: 'SUCCESS',
      ip_address: '127.0.0.1',
      details: `Granted READ permission to Bob Viewer (viewer@trustvault.com).`
    });

    console.log('[TrustVault] Seed data created successfully:');
    console.log('  - Admin: admin@trustvault.com / Password123!');
    console.log('  - Owner: owner@trustvault.com / Password123!');
    console.log('  - Viewer: viewer@trustvault.com / Password123!');
    console.log('  - Outsider Viewer: outsider@trustvault.com / Password123!');
  }
}

module.exports = {
  db,
  run,
  get,
  all,
  logAuditEvent,
  computeEntryHash,
  initDb
};
