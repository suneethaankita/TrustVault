# THREATS.md — TrustVault Security & Threat Analysis
**Author:** Ankita Suneetha  
**Challenge:** Snovasys Fresher Hiring Challenge 2026 (RISE)  
**System:** TrustVault — Secure Document Sharing with a Real Audit Trail  

---

## Executive Summary
TrustVault is built under a **Zero-Trust Document Security Model**. This threat model analyzes potential adversarial vectors aimed at bypassing document authorization, stealing confidential enterprise records, tampering with audit evidence, and evading detection.

Each threat entry documents:
1. **Attack Vector & Mechanics**: How an adversary would attempt exploitation.
2. **Impact**: Potential damage if unmitigated.
3. **Mitigation Implemented**: The specific technical defense deployed in TrustVault.
4. **Automated Verification**: How our automated test suite proves this defense holds.
5. **Accepted Residual Risk**: Technical trade-offs consciously accepted and why.

---

## Threat Matrix

### 1. Insecure Direct Object References (IDOR) on File Downloads
- **Attack Scenario:** An authenticated viewer (e.g. `viewer@trustvault.com`) discovers a document ID belonging to another department (e.g., `/api/documents/8f7c1a2d-4e9b.../download`) and directly requests it via `curl` or browser.
- **Impact:** High. Complete breach of confidentiality.
- **Mitigation Implemented:** 
  The server *never* trusts client-provided IDs or assumes permission from route parameters. In `controllers/documentController.js`, `evaluateAccess(docId, req.user.id)` performs a database lookup on every single request. If no explicit row exists in `permissions` mapping `document_id` to `user_id` and the user is not `owner_id`, HTTP `403 Forbidden` is returned immediately.
- **Verification:** Test #3 in `tests/security.test.js` proves that Charlie Outsider requesting Alice's confidential salary document receives `NO_PERMISSION` / `403 Forbidden`.
- **Accepted Risk:** UUIDs have 122 bits of entropy, preventing brute-force enumeration, but authorization checks occur regardless of whether an ID is guessed.

---

### 2. Stale Permission / Delayed Revocation (JWT Claim Caching Vulnerability)
- **Attack Scenario:** An owner shares a sensitive contract with an employee, then fires the employee and clicks "Revoke Access". If permissions are embedded as claims inside the user's JWT token, the employee can continue downloading the file until the 8-hour token expires.
- **Impact:** Critical. The problem statement explicitly requires: *"Taking access away works immediately. Whatever you have issued to that person before that moment stops working."*
- **Mitigation Implemented:**
  **Permissions are strictly stateful and queried at the database tier on every single request.** The JWT token only carries user identity (`id`, `email`), which is verified for session validity. Document permissions are NEVER stored in the JWT or in browser memory. When an owner calls `DELETE /api/documents/:id/permissions/:userId`, the permission record is removed from SQLite instantly. The very next millisecond download request fails with 403.
- **Verification:** Test #4 in `tests/security.test.js` validates immediate revocation within the same execution cycle.
- **Accepted Risk:** An extra indexed SQL query per download request. For our scale, SQLite handles >50,000 read queries/sec, making this latency overhead (<0.5ms) negligible compared to security correctness.

---

### 3. Direct Static URL Bypass (Unauthenticated File Path Exposure)
- **Attack Scenario:** Attackers look at network traffic or inspect HTML to find static file assets (e.g. `https://vault.com/uploads/Executive_Salary_2026.pdf`). If files are served via static file middleware (`express.static`), anyone with the URL bypasses all authorization code.
- **Impact:** Critical. Renders all application-level authorization code useless.
- **Mitigation Implemented:**
  1. The vault storage directory (`/storage/vault_files/`) is located **outside** the public web directory (`/public/`).
  2. There is no route or static middleware exposing `/storage/`.
  3. The only way to retrieve bytes is through the authenticated endpoint `/api/documents/:id/download`, which enforces `evaluateAccess()` before streaming via `fs.createReadStream().pipe(res)`.
- **Verification:** Verified by directory architecture and lack of any static routing pointing to `storage/`.

---

### 4. Path Traversal & Arbitrary File Overwrite
- **Attack Scenario:** An attacker uploads a file named `../../../../etc/passwd` or `..\..\Windows\System32\cmd.exe` or overwrites a critical database file.
- **Impact:** Remote code execution, server compromise, or unauthorized file overwrites.
- **Mitigation Implemented:**
  1. Multer is configured with custom storage where `file.originalname` is **discarded for filesystem operations**.
  2. Every file on disk is assigned a cryptographically random UUID v4 (`crypto.randomUUID() + ext`).
  3. Original filenames are stored only as a database metadata string and escaped during `Content-Disposition` header generation.
- **Verification:** Filesystem inspection reveals zero user-controlled names on disk.

---

### 5. Audit Trail Tampering & Log Deletion
- **Attack Scenario:** A rogue employee or insider with access to the database modifies or deletes audit logs to erase evidence of unauthorized file downloads.
- **Impact:** High. Failure of non-negotiable requirement: *"An audit trail that can be quietly altered is not evidence, and we will ask you what stops that."*
- **Mitigation Implemented:**
  **Cryptographic SHA-256 Hash Chaining (Audit Blockchain):**
  Each audit log entry contains `previous_hash` and `entry_hash`.
  `entry_hash = SHA-256(previous_hash + timestamp + actor_email + action + resource_id + status + details)`.
  Genesis starts with 64 zeros. 
  The `/api/audit/verify` endpoint verifies the integrity of every single block sequentially. If any log is altered, edited, or deleted, the cryptographic chain breaks immediately and highlights the exact compromised record.
- **Verification:** Test #6 in `tests/security.test.js` modifies an entry and verifies that cryptographic validation fails immediately.

---

### 6. Information Leakage through Search & Metadata Enumeration
- **Attack Scenario:** A viewer cannot download a document, but by using the search API (`/api/documents?search=Project_X`), they can see document titles, categories, and owner names, revealing sensitive corporate mergers or salary details.
- **Impact:** Medium. Metadata leakage.
- **Mitigation Implemented:**
  In `controllers/documentController.js:listDocuments()`, the SQL query explicitly filters:
  `WHERE (d.owner_id = ? OR p.user_id = ?)`
  A user can ONLY search across documents they already own or have been granted access to. An unauthorized user searching for "Salary" returns an empty set `[]`.
- **Verification:** API returns zero records for documents where no permission grant exists.

---

### 7. Unrestricted File Upload / Malicious Executables
- **Attack Scenario:** An attacker uploads an executable web shell (`shell.php`, `backdoor.exe`, `.html` with malicious JavaScript for Stored XSS).
- **Impact:** Remote Code Execution (RCE) or Stored Cross-Site Scripting (XSS).
- **Mitigation Implemented:**
  1. Strict whitelist of extensions: `.pdf`, `.docx`, `.txt`, `.png`, `.jpg`, `.jpeg`, `.csv`, `.xlsx`.
  2. Strict MIME type validation: Executable formats are rejected by Multer.
  3. HTML files are strictly disallowed to prevent stored XSS attacks when viewing files.
  4. Content-Disposition is set to `attachment`, forcing download rather than browser execution.
- **Verification:** Multer rejects any extension outside the whitelist with `400 Bad Request`.

---

### 8. Privilege Escalation by Viewers (Granting/Revoking Other Users)
- **Attack Scenario:** A viewer with `READ` access makes a `POST /api/documents/:id/permissions` request to give themselves `EDIT` permission or grant access to an accomplice.
- **Impact:** High. Unauthorized permission expansion.
- **Mitigation Implemented:**
  In `grantPermission()` and `revokePermission()`, the server executes:
  `if (!access.authorized || !access.isOwner) return res.status(403);`
  Only the original document creator (`doc.owner_id === req.user.id`) has the authority to grant or revoke access. All unauthorized grant attempts trigger a `status = 'DENIED'` audit log.
- **Verification:** Unit tests confirm 403 on non-owner grant attempts.

---

### 9. Replay Attacks & Credential Brute-Force
- **Attack Scenario:** An attacker sends automated dictionary attacks against `/api/auth/login`.
- **Impact:** Account takeover.
- **Mitigation Implemented:**
  1. Rate limiting via `express-rate-limit`: Authentication endpoints (`/api/auth/*`) are capped at 20 attempts per 15 minutes per IP.
  2. Passwords hashed using bcrypt with salt rounds = 10.
  3. Failed login attempts are logged to the audit trail with IP address and timestamp.
- **Verification:** Rapid requests trigger HTTP 429 Too Many Requests.

---

### 10. Physical Disk Snooping & Storage Byte Tampering
- **Attack Scenario:** An attacker gains access to the underlying server disk image or container volume and reads stored files directly, or flips bits in a stored document to corrupt company data silently.
- **Impact:** High. Confidentiality breach or undetected data corruption.
- **Mitigation Implemented:**
  1. All files written to disk are encrypted using **AES-256-GCM** authenticated encryption (`cryptoVault.js`).
  2. The format prepends a 16-byte random IV and 16-byte GCM Authentication Tag before the ciphertext.
  3. When an authorized user downloads or previews a file, the server validates the AuthTag during decryption. If any single byte on disk was tampered with, decryption fails immediately and alerts the system.
- **Verification:** Test #8 in `tests/security.test.js` verifies ciphertext opacity and confirms that flipping a single byte in storage triggers an authentication failure.

---

## Consciously Accepted Residual Risks & Justification (Honesty Section)

As required by the challenge guidelines, here are the architectural trade-offs consciously accepted and why:

1. **Local Encrypted Disk vs. Cloud Object Storage (S3 / KMS):**
   - *Risk:* If the host server's local disk fails or is wiped, uploaded files would be lost without a separate backup.
   - *Reason for Acceptance:* To make TrustVault completely self-contained, zero-dependency, and instantly runnable for evaluators from a clean clone without requiring paid AWS S3 credentials or cloud setup. In a multi-tenant cloud deployment, the storage backend would swap to AWS S3 with private buckets and pre-signed URLs with 60-second expiration.
2. **Single Derived Master Key vs. Per-File Envelope Encryption:**
   - *Risk:* All files on an instance are encrypted using the derived server master key (`VAULT_ENCRYPTION_KEY`) rather than generating a distinct random Data Encryption Key (DEK) wrapped by an external Hardware Security Module (HSM).
   - *Reason for Acceptance:* For this standalone deployment, AES-256-GCM provides authenticated defense without requiring an external KMS provider subscription.
3. **Admin Viewing Document Metadata:**
   - *Risk:* The Administrator role can view the global audit log containing document titles and actions.
   - *Reason for Acceptance:* Auditors need to see what actions occurred. However, the Admin **cannot** download the file content unless Alice explicitly grants them `READ` access, strictly preserving zero-trust segregation of duties.
