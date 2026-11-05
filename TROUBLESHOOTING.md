# TrustVault — Troubleshooting & Diagnostics Guide

This guide covers common operational, deployment, and debugging issues when running or evaluating TrustVault.

---

## 🛠️ Common Scenarios & Resolutions

### 1. "Port 3000 is already in use"
* **Symptom:** `Error: listen EADDRINUSE: address already in use :::3000`
* **Cause:** Another background Node.js process or local development server is running on port 3000.
* **Resolution:**
  Set a custom port before starting:
  ```bash
  PORT=3001 npm start
  ```
  Or kill the existing process:
  ```bash
  # Windows PowerShell:
  Stop-Process -Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess -Force
  ```

---

### 2. "Database is locked" (SQLite Busy)
* **Symptom:** `SQLITE_BUSY: database is locked`
* **Cause:** Multiple concurrent writer processes attempting to modify SQLite simultaneously without WAL mode.
* **Resolution:**
  TrustVault runs SQLite with standard transactions and sequential write queries. Ensure only one server instance is attached to `trustvault.db` at a time. If testing under heavy multi-threaded loads, configure WAL mode:
  ```sql
  PRAGMA journal_mode = WAL;
  ```

---

### 3. File Download Returns 403 Forbidden
* **Symptom:** Evaluator clicks "Download" and receives: `Access Denied: You do not have authorization to download or read this file.`
* **Diagnostic Check:**
  1. Check the logged-in role. If signed in as `outsider@trustvault.com` (Charlie Outsider), this is the **intended zero-trust behavior**! Charlie has no permission row for Alice's confidential documents.
  2. Switch to **Alice (Owner)** or **Bob (Viewer)** using the top Quick Access bar to download.
  3. Verify the event in the Admin audit log (`/api/audit`), where this refusal is logged under `status: DENIED`.

---

### 4. Integrity Verification Failure on `/api/audit/verify`
* **Symptom:** Cryptographic verification alert: `Tampering detected at log entry #X`
* **Cause:** An external direct SQL update was executed against the `audit_logs` table, or a row was manually deleted.
* **Resolution:**
  TrustVault's SHA-256 hash chaining is functioning correctly! The failure proves the audit blockchain detected the unauthorized database edit. To restore a clean ledger for evaluation, re-seed the database:
  ```bash
  npm run seed
  ```

---

### 5. File Upload Rejection (400 Bad Request)
* **Symptom:** `File type rejected. Allowed extensions: .pdf, .docx, .txt, .png, .jpg, .jpeg, .csv, .xlsx`
* **Cause:** Attempting to upload executable or dangerous file formats (e.g. `.exe`, `.sh`, `.php`, `.html`).
* **Resolution:** Upload files matching the approved enterprise document whitelist.
