const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const multer = require('multer');

const { initDb } = require('./database');
const { authenticateToken, requireRole } = require('./middleware/auth');
const authController = require('./controllers/authController');
const documentController = require('./controllers/documentController');
const auditController = require('./controllers/auditController');

const app = express();
const PORT = process.env.PORT || 3000;

// CRITICAL: Trust reverse proxy (Render, AWS, Nginx) so HTTPS and client IPs are resolved correctly
app.set('trust proxy', 1);

// 1. Security Headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false
  })
);

// 2. Request Parsing
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

// 3. Brute Force Protection (Rate Limiting)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 login/register requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts from this IP. Please try again after 15 minutes.' }
});

const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 120, // 120 requests per minute
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', generalLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// 4. Secure Multer File Storage Configuration
const storageDir = path.join(__dirname, 'storage', 'vault_files');
if (!fs.existsSync(storageDir)) {
  fs.mkdirSync(storageDir, { recursive: true });
}

// Allowed file extensions and corresponding MIME types whitelist
const ALLOWED_EXTENSIONS = new Set(['.pdf', '.docx', '.txt', '.png', '.jpg', '.jpeg', '.csv', '.xlsx']);
const ALLOWED_MIME_TYPES = new Set([
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'text/plain',
  'text/csv',
  'image/png',
  'image/jpeg',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
]);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, storageDir);
  },
  filename: (req, file, cb) => {
    // SECURITY: Discard original user filename completely to avoid path traversal / overwrite attacks
    const ext = path.extname(file.originalname).toLowerCase();
    const safeUUID = crypto.randomUUID();
    cb(null, `${safeUUID}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();

    // Check against extension whitelist
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      return cb(new Error(`File type rejected. Allowed extensions: ${Array.from(ALLOWED_EXTENSIONS).join(', ')}`));
    }

    // Check MIME type
    if (!ALLOWED_MIME_TYPES.has(file.mimetype)) {
      return cb(new Error('Invalid MIME type. File format not permitted.'));
    }

    cb(null, true);
  }
});

// 5. API Routes

// --- Authentication & User Management ---
app.post('/api/auth/register', authController.register);
app.post('/api/auth/login', authController.login);
app.get('/api/auth/me', authenticateToken, authController.getCurrentUser);
app.post('/api/auth/logout', authenticateToken, authController.logout);
app.get('/api/auth/users', authenticateToken, authController.listUsers);

// --- Documents ---
// Upload document
app.post('/api/documents/upload', authenticateToken, (req, res, next) => {
  upload.single('document')(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File exceeds maximum allowed size of 10MB.' });
      }
      return res.status(400).json({ error: err.message || 'File upload rejected.' });
    }
    next();
  });
}, documentController.uploadDocument);

// List visible documents (Search & filter)
app.get('/api/documents', authenticateToken, documentController.listDocuments);

// Document details & metadata
app.get('/api/documents/:id', authenticateToken, documentController.getDocument);

// Download document (Critical dynamic authorization point)
app.get('/api/documents/:id/download', authenticateToken, documentController.downloadDocument);

// Update document metadata
app.put('/api/documents/:id', authenticateToken, documentController.updateDocument);

// Delete document (Owner strictly)
app.delete('/api/documents/:id', authenticateToken, documentController.deleteDocument);

// --- Permissions Management (Owner strictly) ---
app.post('/api/documents/:id/permissions', authenticateToken, documentController.grantPermission);
app.delete('/api/documents/:id/permissions/:userId', authenticateToken, documentController.revokePermission);
app.get('/api/documents/:id/permissions', authenticateToken, documentController.listDocumentPermissions);

// --- Audit Trail & Cryptographic Verification ---
// Administrator: View all audit activity
app.get('/api/audit', authenticateToken, requireRole('ADMIN'), auditController.getAuditLogs);

// Administrator: Cryptographically verify audit log hash chain integrity
app.get('/api/audit/verify', authenticateToken, requireRole('ADMIN'), auditController.verifyAuditIntegrity);

// Document Owner: View audit trail specifically for their document
app.get('/api/audit/document/:id', authenticateToken, auditController.getDocumentAuditLogs);

// 6. Serve Frontend Static Client
app.use(express.static(path.join(__dirname, 'public')));

// Catch-all route to serve SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize database and start server
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`======================================================`);
      console.log(`🔒 TrustVault Platform running on http://localhost:${PORT}`);
      console.log(`🛡️  Tamper-Evident Audit Trail & Dynamic RBAC Active`);
      console.log(`======================================================`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });

module.exports = app;
