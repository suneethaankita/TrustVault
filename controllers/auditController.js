const { all, get, computeEntryHash } = require('../database');

// 1. Get Audit Logs (Administrator View)
async function getAuditLogs(req, res) {
  try {
    const { status, action, actorEmail, startDate, endDate, limit = 100 } = req.query;

    let sql = 'SELECT * FROM audit_logs WHERE 1=1';
    const params = [];

    if (status && ['SUCCESS', 'DENIED'].includes(status)) {
      sql += ' AND status = ?';
      params.push(status);
    }

    if (action && action.trim()) {
      sql += ' AND action = ?';
      params.push(action.trim());
    }

    if (actorEmail && actorEmail.trim()) {
      sql += ' AND actor_email LIKE ?';
      params.push(`%${actorEmail.trim()}%`);
    }

    if (startDate) {
      sql += ' AND timestamp >= ?';
      params.push(startDate);
    }
    if (endDate) {
      sql += ' AND timestamp <= ?';
      params.push(endDate);
    }

    sql += ' ORDER BY id DESC LIMIT ?';
    params.push(Math.min(parseInt(limit, 10) || 100, 500));

    const logs = await all(sql, params);
    res.json({ logs });
  } catch (err) {
    console.error('Audit logs error:', err);
    res.status(500).json({ error: 'Failed to retrieve audit logs.' });
  }
}

// 2. Get Audit Trail for a Specific Document (Owner Access)
async function getDocumentAuditLogs(req, res) {
  try {
    const docId = req.params.id;

    // Check ownership
    const doc = await get('SELECT * FROM documents WHERE id = ?', [docId]);
    if (!doc) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    // Only owner or admin can see document-specific audit history
    if (doc.owner_id !== req.user.id && req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Access Denied: Only document owner or administrator can view audit logs.' });
    }

    const logs = await all(
      `SELECT * FROM audit_logs
       WHERE resource_id = ?
       ORDER BY id DESC LIMIT 100`,
      [docId]
    );

    res.json({ document: doc, logs });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve document audit trail.' });
  }
}

// 3. Cryptographically Verify Audit Trail Integrity
// Iterates from the first block to the last block, recomputing SHA-256 hashes
async function verifyAuditIntegrity(req, res) {
  try {
    const logs = await all('SELECT * FROM audit_logs ORDER BY id ASC');

    if (logs.length === 0) {
      return res.json({
        verified: true,
        message: 'Audit log is empty. Integrity intact.',
        count: 0
      });
    }

    let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';

    for (let i = 0; i < logs.length; i++) {
      const entry = logs[i];

      // Check if previous_hash matches the chain
      if (entry.previous_hash !== expectedPrevHash) {
        return res.status(400).json({
          verified: false,
          compromisedAtId: entry.id,
          reason: 'CHAIN_BROKEN_PREVIOUS_HASH_MISMATCH',
          message: `Tampering detected at log entry #${entry.id}! Previous hash link was broken.`
        });
      }

      // Recompute expected hash of this entry
      const recalculatedHash = computeEntryHash(entry.previous_hash, {
        timestamp: entry.timestamp,
        actor_email: entry.actor_email,
        action: entry.action,
        resource_type: entry.resource_type,
        resource_id: entry.resource_id,
        status: entry.status,
        ip_address: entry.ip_address,
        details: entry.details || ''
      });

      if (recalculatedHash !== entry.entry_hash) {
        return res.status(400).json({
          verified: false,
          compromisedAtId: entry.id,
          reason: 'CONTENT_MODIFICATION_DETECTED',
          message: `Tampering detected at log entry #${entry.id}! Record contents were modified after logging.`
        });
      }

      expectedPrevHash = entry.entry_hash;
    }

    res.json({
      verified: true,
      message: 'Audit trail cryptographic verification passed. All records are intact, strictly sequential, and tamper-free.',
      totalRecordsVerified: logs.length,
      latestChainHash: expectedPrevHash
    });
  } catch (err) {
    console.error('Integrity verification error:', err);
    res.status(500).json({ error: 'Failed to verify audit log integrity.' });
  }
}

module.exports = {
  getAuditLogs,
  getDocumentAuditLogs,
  verifyAuditIntegrity
};
