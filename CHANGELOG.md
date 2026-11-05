# TrustVault — Engineering Changelog

All notable changes and architectural iterations to the TrustVault platform across the development lifecycle are documented in this file.

---

## [1.0.0] - 2026-11-05 (Production Release)

### Added
- **AES-256-GCM Storage Encryption:** Added authenticated symmetric encryption at rest for all stored files on physical disk (`utils/cryptoVault.js`).
- **In-Memory Secure Preview:** Added `/api/documents/:id/preview` supporting decrypted in-memory previews for `.txt`, `.csv`, `.png`, and `.jpg` files without leaving temporary unencrypted files on disk.
- **Metadata Management Modal:** Added in-app title and category editing for Document Owners and users with `EDIT` permissions (`modal-edit-doc`).
- **Multi-Factor Search & Filtering:** Added Owner Email, Start Date, and End Date range filtering to the Vault document explorer (`#advanced-filters`).
- **Comprehensive Documentation Suite:** Added `ARCHITECTURE.md`, `DATABASE_SCHEMA.md`, `API_DOCUMENTATION.md`, `SECURITY.md`, `DEPLOYMENT.md`, `TESTING.md`, `TROUBLESHOOTING.md`, and audit reports.

---

## [0.9.0] - 2026-11-04

### Added
- **Cryptographic Audit Blockchain:** Implemented SHA-256 hash chaining on all audit logs with `/api/audit/verify` verification engine.
- **Denied Event Logging:** Enabled automatic capture of rejected access attempts with `status: DENIED` for forensic auditing.
- **Administrative Oversight UI:** Added admin dashboard tab with real-time audit log filtering by status and cryptographic integrity verification.

---

## [0.5.0] - 2026-11-03

### Added
- **Dynamic Authorization Checkpoint:** Implemented `evaluateAccess(docId, userId)` as the single source of truth on all document download requests.
- **Immediate Permission Revocation:** Stateful database-tier permission deletes providing zero-millisecond revocation without token delays.
- **Physical Storage Isolation:** Isolated file storage outside the public web root with random UUID filenames.

---

## [0.1.0] - 2026-11-02

### Added
- **Initial Genesis Architecture:** Express server setup with Helmet security headers, rate limiting, and cookie-based JWT authentication.
- **Three Core Roles:** Implemented ADMIN, OWNER, and VIEWER roles with database schemas and automated seeding.
