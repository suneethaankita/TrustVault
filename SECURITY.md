# TrustVault — Security Policy & Defense-in-Depth Specification

**Candidate:** ANKITA SUNEETHA  
**Project:** TrustVault  
**Classification:** Defense-Grade Enterprise Document Platform  

---

## 🛡️ Security Philosophy: Zero-Trust Document Architecture

TrustVault operates under the foundational premise: **"Never trust, always verify."**  
In traditional CRUD applications, security is often implemented as cosmetic UI checks (disabling buttons, hiding links) or coarse-grained route guards. TrustVault enforces fine-grained authorization at the exact point of data consumption.

---

## 🔒 Implemented Security Controls

### 1. Dynamic Server-Side Authorization Checkpoint
* **Location:** `controllers/documentController.js:evaluateAccess()`
* **Mechanism:** Every request to download, preview, inspect metadata, edit, or delete a document queries the active relational access state directly from the database.
* **Why Not JWT Claims:** Caching permissions inside JWT claims violates the non-negotiable requirement for immediate revocation. An unexpired token with embedded claims could be used hours after access was rescinded.

### 2. Immediate Revocation (Zero Latency)
* When an owner deletes a permission grant, the relational row in the `permissions` table is removed in an ACID transaction.
* The very next millisecond download attempt fails with HTTP 403 Forbidden.

### 3. Physical Storage Isolation & Anti-Traversal
* Uploaded files are stored in `/storage/vault_files/`, located completely outside the public web root.
* No static file middleware serves the storage folder. Direct URLs return 404.
* Files on disk are renamed to random UUIDs v4 (`${crypto.randomUUID()}${ext}`), neutralizing path traversal attacks (`../../`) and filename collisions.

### 4. AES-256-GCM Authenticated Encryption at Rest
* Stored files on physical disk are encrypted with **AES-256-GCM**.
* Format: `[16 bytes IV][16 bytes AuthTag][Ciphertext]`.
* Decryption occurs strictly in-memory during authorized streaming.
* Tampering with bytes on disk causes GCM authentication verification to fail, protecting against unauthorized server-level modifications.

### 5. Tamper-Evident SHA-256 Chained Audit Blockchain
* Every event generates an immutable ledger block:
  `entry_hash = SHA-256(previous_hash + timestamp + actor + action + status + ip + details)`
* **Failed / Unauthorized attempts** are explicitly logged (`status = 'DENIED'`), allowing security teams to detect reconnaissance and brute-force attempts.
* `/api/audit/verify` iterates from genesis (64 zeros) through all records to mathematically prove zero tampering.

### 6. Brute-Force Rate Limiting
* Express rate limiters protect authentication endpoints (`/api/auth/*`), capping requests at 20 per 15 minutes per IP.
* General API endpoints are protected against Denial of Service with 120 req/min limits.

### 7. Transport Security & Security Headers
* **Helmet:** Configures Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), X-Content-Type-Options: `nosniff`, and X-Frame-Options: `DENY` to prevent clickjacking and MIME-type sniffing.
* Cookies are flagged `HttpOnly`, `SameSite=Lax`, and `Secure` in production.
