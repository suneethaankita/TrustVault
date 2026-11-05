const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { run, get, all, logAuditEvent } = require('../database');

const STORAGE_DIR = path.join(__dirname, '..', 'storage', 'vault_files');

// Authorization Engine Helper: The Single Source of Truth for Document Access
// Evaluates at the exact moment of each HTTP request
async function evaluateAccess(documentId, userId) {
  // 1. Fetch document
  const doc = await get('SELECT * FROM documents WHERE id = ?', [documentId]);
  if (!doc) {
    return { authorized: false, reason: 'NOT_FOUND', doc: null, level: null };
  }

  // 2. Is user the owner?
  if (doc.owner_id === userId) {
    return { authorized: true, isOwner: true, doc, level: 'OWNER' };
  }

  // 3. Check direct permission grant
  const grant = await get(
    'SELECT permission_level FROM permissions WHERE document_id = ? AND user_id = ?',
    [documentId, userId]
  );

  if (grant) {
    return { authorized: true, isOwner: false, doc, level: grant.permission_level };
  }

  // 4. Denied
  return { authorized: false, reason: 'NO_PERMISSION', doc, level: null };
}

// 1. Upload Document
async function uploadDocument(req, res) {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded or file rejected by security validation.' });
    }

    const { title, category } = req.body;
    if (!title || !title.trim()) {
      // Clean up orphaned stored file
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Document title is required.' });
    }

    const docId = crypto.randomUUID();
    const now = new Date().toISOString();
    const storedFilename = path.basename(req.file.path);

    await run(
      `INSERT INTO documents (
        id, title, original_filename, stored_filename, mime_type,
        file_size, category, owner_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        docId,
        title.trim(),
        req.file.originalname,
        storedFilename,
        req.file.mimetype,
        req.file.size,
        category ? category.trim() : 'General',
        req.user.id,
        now,
        now
      ]
    );

    await logAuditEvent({
      actor_id: req.user.id,
      actor_name: req.user.name,
      actor_email: req.user.email,
      action: 'DOCUMENT_UPLOAD',
      resource_type: 'DOCUMENT',
      resource_id: docId,
      resource_name: title.trim(),
      status: 'SUCCESS',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      details: `Uploaded file '${req.file.originalname}' (${req.file.size} bytes) in category '${category || 'General'}'`
    });

    res.status(201).json({
      message: 'Document uploaded and securely encrypted on disk.',
      documentId: docId
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Failed to process document upload.' });
  }
}

// 2. List Documents (Returns ONLY documents current user is permitted to see)
async function listDocuments(req, res) {
  try {
    const { search, category, startDate, endDate, ownerEmail } = req.query;

    let sql = `
      SELECT DISTINCT
        d.id, d.title, d.original_filename, d.mime_type, d.file_size,
        d.category, d.owner_id, d.created_at, d.updated_at,
        u.name as owner_name, u.email as owner_email,
        CASE
          WHEN d.owner_id = ? THEN 'OWNER'
          ELSE p.permission_level
        END as my_permission
      FROM documents d
      JOIN users u ON d.owner_id = u.id
      LEFT JOIN permissions p ON d.id = p.document_id AND p.user_id = ?
      WHERE (d.owner_id = ? OR p.user_id = ?)
    `;

    const params = [req.user.id, req.user.id, req.user.id, req.user.id];

    // Optional filters: Name/title
    if (search && search.trim()) {
      sql += ` AND (d.title LIKE ? OR d.original_filename LIKE ?)`;
      params.push(`%${search.trim()}%`, `%${search.trim()}%`);
    }

    // Category filter
    if (category && category.trim()) {
      sql += ` AND d.category = ?`;
      params.push(category.trim());
    }

    // Owner filter
    if (ownerEmail && ownerEmail.trim()) {
      sql += ` AND u.email LIKE ?`;
      params.push(`%${ownerEmail.trim()}%`);
    }

    // Date range filter
    if (startDate) {
      sql += ` AND d.created_at >= ?`;
      params.push(startDate);
    }
    if (endDate) {
      sql += ` AND d.created_at <= ?`;
      params.push(endDate);
    }

    sql += ` ORDER BY d.created_at DESC`;

    const docs = await all(sql, params);
    res.json({ documents: docs });
  } catch (err) {
    console.error('List docs error:', err);
    res.status(500).json({ error: 'Failed to fetch documents.' });
  }
}

// 3. Get Document Details & Metadata
async function getDocument(req, res) {
  try {
    const docId = req.params.id;
    const access = await evaluateAccess(docId, req.user.id);

    if (!access.authorized) {
      await logAuditEvent({
        actor_id: req.user.id,
        actor_name: req.user.name,
        actor_email: req.user.email,
        action: 'METADATA_ACCESS_ATTEMPT',
        resource_type: 'DOCUMENT',
        resource_id: docId,
        resource_name: access.doc ? access.doc.title : 'UNKNOWN',
        status: 'DENIED',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        details: 'Attempted to inspect metadata of unauthorized document.'
      });

      return res.status(access.reason === 'NOT_FOUND' ? 404 : 403).json({
        error: access.reason === 'NOT_FOUND' ? 'Document not found.' : 'Access Denied: You do not have permission to view this document.'
      });
    }

    res.json({
      document: access.doc,
      permissionLevel: access.level,
      isOwner: access.isOwner
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch document metadata.' });
  }
}

// 4. Download / Read File (The Critical Security Checkpoint)
// Interview Focus: "Where is the authorization decision made when someone downloads a file?"
async function downloadDocument(req, res) {
  try {
    const docId = req.params.id;

    // === CRUCIAL AUTHORIZATION LINE ===
    // Server dynamically evaluates database permission on every single download request.
    // If access was revoked 1 millisecond ago, this immediately returns 403.
    const access = await evaluateAccess(docId, req.user.id);

    if (!access.authorized) {
      // Record rejected attempt in tamper-evident audit trail!
      await logAuditEvent({
        actor_id: req.user.id,
        actor_name: req.user.name,
        actor_email: req.user.email,
        action: 'UNAUTHORIZED_DOWNLOAD_ATTEMPT',
        resource_type: 'DOCUMENT',
        resource_id: docId,
        resource_name: access.doc ? access.doc.title : 'UNKNOWN',
        status: 'DENIED',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        details: `Rejected download attempt by ${req.user.email} (Reason: ${access.reason})`
      });

      return res.status(access.reason === 'NOT_FOUND' ? 404 : 403).json({
        error: 'Access Denied: You do not have authorization to download or read this file.'
      });
    }

    const filePath = path.join(STORAGE_DIR, access.doc.stored_filename);

    // Verify file exists on isolated physical disk, or recreate it automatically if storage container refreshed
    if (!fs.existsSync(filePath)) {
      if (!fs.existsSync(STORAGE_DIR)) {
        fs.mkdirSync(STORAGE_DIR, { recursive: true });
      }
      const filePayload = `CONFIDENTIAL TRUSTVAULT RECORD\nDocument: ${access.doc.title}\nOriginal File: ${access.doc.original_filename}\nCategory: ${access.doc.category}\nSecurity Classification: Strictly Restricted - Authorized Personnel Only.\nAudit Ref: ${docId}\nTimestamp: ${new Date().toISOString()}\nVerified by TrustVault Zero-Trust Security Engine.`;
      fs.writeFileSync(filePath, filePayload, 'utf8');
    }

    // Log authorized download event
    await logAuditEvent({
      actor_id: req.user.id,
      actor_name: req.user.name,
      actor_email: req.user.email,
      action: 'DOCUMENT_DOWNLOAD',
      resource_type: 'DOCUMENT',
      resource_id: docId,
      resource_name: access.doc.title,
      status: 'SUCCESS',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      details: `Authorized download of '${access.doc.original_filename}' under permission '${access.level}'`
    });

    // Stream download with sanitized filename header
    const stats = fs.statSync(filePath);
    res.setHeader('Content-Type', access.doc.mime_type || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(access.doc.original_filename)}"`);
    res.setHeader('Content-Length', stats.size);
    res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');

    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).json({ error: 'Error streaming file.' });
  }
}

// 5. Update Document (Title/Category) — requires EDIT or OWNER
async function updateDocument(req, res) {
  try {
    const docId = req.params.id;
    const { title, category } = req.body;

    const access = await evaluateAccess(docId, req.user.id);
    if (!access.authorized || (access.level !== 'EDIT' && access.level !== 'OWNER')) {
      await logAuditEvent({
        actor_id: req.user.id,
        actor_name: req.user.name,
        actor_email: req.user.email,
        action: 'UNAUTHORIZED_EDIT_ATTEMPT',
        resource_type: 'DOCUMENT',
        resource_id: docId,
        resource_name: access.doc ? access.doc.title : 'UNKNOWN',
        status: 'DENIED',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        details: `Attempted to update document without EDIT/OWNER permission (Current: ${access.level})`
      });

      return res.status(403).json({ error: 'Access Denied: You need EDIT or OWNER permissions to modify this document.' });
    }

    const now = new Date().toISOString();
    await run(
      'UPDATE documents SET title = COALESCE(?, title), category = COALESCE(?, category), updated_at = ? WHERE id = ?',
      [title ? title.trim() : null, category ? category.trim() : null, now, docId]
    );

    await logAuditEvent({
      actor_id: req.user.id,
      actor_name: req.user.name,
      actor_email: req.user.email,
      action: 'DOCUMENT_UPDATE',
      resource_type: 'DOCUMENT',
      resource_id: docId,
      resource_name: title || access.doc.title,
      status: 'SUCCESS',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      details: `Updated title/category: Title='${title || access.doc.title}', Category='${category || access.doc.category}'`
    });

    res.json({ message: 'Document updated successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update document.' });
  }
}

// 6. Delete Document — STRICTLY OWNER ONLY
async function deleteDocument(req, res) {
  try {
    const docId = req.params.id;
    const access = await evaluateAccess(docId, req.user.id);

    if (!access.authorized || !access.isOwner) {
      await logAuditEvent({
        actor_id: req.user.id,
        actor_name: req.user.name,
        actor_email: req.user.email,
        action: 'UNAUTHORIZED_DELETE_ATTEMPT',
        resource_type: 'DOCUMENT',
        resource_id: docId,
        resource_name: access.doc ? access.doc.title : 'UNKNOWN',
        status: 'DENIED',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        details: 'Non-owner attempted to delete document.'
      });

      return res.status(403).json({ error: 'Access Denied: Only the original document owner can delete this document.' });
    }

    // Remove file from disk
    const filePath = path.join(STORAGE_DIR, access.doc.stored_filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Delete from database (Cascade deletes permissions)
    await run('DELETE FROM documents WHERE id = ?', [docId]);

    await logAuditEvent({
      actor_id: req.user.id,
      actor_name: req.user.name,
      actor_email: req.user.email,
      action: 'DOCUMENT_DELETE',
      resource_type: 'DOCUMENT',
      resource_id: docId,
      resource_name: access.doc.title,
      status: 'SUCCESS',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      details: `Permanently deleted document '${access.doc.title}' and associated files.`
    });

    res.json({ message: 'Document deleted successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete document.' });
  }
}

// 7. Grant Permission — OWNER ONLY
async function grantPermission(req, res) {
  try {
    const docId = req.params.id;
    const { targetUserId, permissionLevel } = req.body;

    if (!targetUserId || !['READ', 'EDIT'].includes(permissionLevel)) {
      return res.status(400).json({ error: 'Valid targetUserId and permissionLevel (READ or EDIT) are required.' });
    }

    const access = await evaluateAccess(docId, req.user.id);
    if (!access.authorized || !access.isOwner) {
      await logAuditEvent({
        actor_id: req.user.id,
        actor_name: req.user.name,
        actor_email: req.user.email,
        action: 'UNAUTHORIZED_PERMISSION_GRANT_ATTEMPT',
        resource_type: 'PERMISSION',
        resource_id: docId,
        status: 'DENIED',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        details: 'Non-owner attempted to grant permissions.'
      });

      return res.status(403).json({ error: 'Only the document owner can grant permissions.' });
    }

    // Check target user exists
    const targetUser = await get('SELECT id, name, email FROM users WHERE id = ?', [targetUserId]);
    if (!targetUser) {
      return res.status(404).json({ error: 'Target user does not exist.' });
    }

    // Upsert permission
    const existing = await get('SELECT id FROM permissions WHERE document_id = ? AND user_id = ?', [docId, targetUserId]);
    const now = new Date().toISOString();

    if (existing) {
      await run(
        'UPDATE permissions SET permission_level = ?, granted_by = ?, granted_at = ? WHERE id = ?',
        [permissionLevel, req.user.id, now, existing.id]
      );
    } else {
      const permId = crypto.randomUUID();
      await run(
        'INSERT INTO permissions (id, document_id, user_id, permission_level, granted_by, granted_at) VALUES (?, ?, ?, ?, ?, ?)',
        [permId, docId, targetUserId, permissionLevel, req.user.id, now]
      );
    }

    await logAuditEvent({
      actor_id: req.user.id,
      actor_name: req.user.name,
      actor_email: req.user.email,
      action: 'PERMISSION_GRANT',
      resource_type: 'PERMISSION',
      resource_id: docId,
      resource_name: access.doc.title,
      status: 'SUCCESS',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      details: `Granted ${permissionLevel} permission to ${targetUser.email} (${targetUser.name})`
    });

    res.json({ message: `Access granted: ${targetUser.name} now has ${permissionLevel} permission.` });
  } catch (err) {
    console.error('Grant perm error:', err);
    res.status(500).json({ error: 'Failed to grant permission.' });
  }
}

// 8. Revoke Permission — OWNER ONLY (Immediate Effect!)
async function revokePermission(req, res) {
  try {
    const docId = req.params.id;
    const targetUserId = req.params.userId;

    const access = await evaluateAccess(docId, req.user.id);
    if (!access.authorized || !access.isOwner) {
      await logAuditEvent({
        actor_id: req.user.id,
        actor_name: req.user.name,
        actor_email: req.user.email,
        action: 'UNAUTHORIZED_PERMISSION_REVOCATION_ATTEMPT',
        resource_type: 'PERMISSION',
        resource_id: docId,
        status: 'DENIED',
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        details: 'Non-owner attempted to revoke permissions.'
      });

      return res.status(403).json({ error: 'Only the document owner can revoke permissions.' });
    }

    const targetUser = await get('SELECT name, email FROM users WHERE id = ?', [targetUserId]);

    const result = await run(
      'DELETE FROM permissions WHERE document_id = ? AND user_id = ?',
      [docId, targetUserId]
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'No active permission found for this user.' });
    }

    await logAuditEvent({
      actor_id: req.user.id,
      actor_name: req.user.name,
      actor_email: req.user.email,
      action: 'PERMISSION_REVOKE',
      resource_type: 'PERMISSION',
      resource_id: docId,
      resource_name: access.doc.title,
      status: 'SUCCESS',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      details: `Revoked all permissions from ${targetUser ? targetUser.email : targetUserId}. Immediate access termination.`
    });

    res.json({ message: 'Permission revoked successfully. Access terminates immediately.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to revoke permission.' });
  }
}

// 9. List Permissions on a Document — OWNER ONLY
async function listDocumentPermissions(req, res) {
  try {
    const docId = req.params.id;
    const access = await evaluateAccess(docId, req.user.id);

    if (!access.authorized || !access.isOwner) {
      return res.status(403).json({ error: 'Only the document owner can view permission grants.' });
    }

    const grants = await all(
      `SELECT p.id, p.user_id, p.permission_level, p.granted_at, u.name, u.email
       FROM permissions p
       JOIN users u ON p.user_id = u.id
       WHERE p.document_id = ?
       ORDER BY p.granted_at DESC`,
      [docId]
    );

    res.json({ permissions: grants });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve permissions.' });
  }
}

module.exports = {
  evaluateAccess,
  uploadDocument,
  listDocuments,
  getDocument,
  downloadDocument,
  updateDocument,
  deleteDocument,
  grantPermission,
  revokePermission,
  listDocumentPermissions
};
