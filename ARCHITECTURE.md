# TrustVault — Architecture & Engineering Specification

**Candidate:** ANKITA SUNEETHA  
**System:** TrustVault — Defense-Grade Document Platform  
**Target:** Snovasys Fresher Hiring Challenge 2026 (RISE)  

---

## 🏛️ System Overview

TrustVault solves two critical enterprise security failures:
1. **Accidental & Stale Permissions:** Files leaking because access was inherited or because access was revoked in a directory but persisted in cached sessions.
2. **Untraceable Breaches:** An inability to prove mathematically who accessed a document, who attempted to access it, and whether access logs were quietly modified after a breach.

TrustVault treats every file download as an adversarial operation under a **Zero-Trust Model**:
* **Identity != Authorization:** Having a valid user account or valid session token does not grant access to any file.
* **Server-Side Dynamic Evaluation:** Every single file request queries the relational access table synchronously.
* **Tamper-Evident Chained Auditing:** Every action and rejected attempt is hashed into a sequential cryptographic blockchain.
* **AES-256-GCM Storage Encryption:** Files on disk are encrypted at rest with authenticated tags to detect any host-level tampering.

---

## 📐 Architecture Diagram

```text
[ Client Browser / SPA ]
         │
         │  HTTPS (TLS 1.3)
         ▼
[ Express Reverse Proxy Barrier ]
 ├── Helmet Security Headers (CSP, HSTS, X-Frame-Options)
 ├── Rate Limiter (Brute-force protection on /api/auth)
 └── Cookie / Bearer Token Parser
         │
         ▼
[ Authentication Middleware (auth.js) ]
 ├── Verify JWT Signature with Secret
 └── Dynamic DB Lookup: Verify user exists and is active
         │
         ▼
[ Document Controller / Zero-Trust Engine (documentController.js) ]
 ├── evaluateAccess(documentId, userId)
 │    ├── Is user doc.owner_id?  ──► ALLOW (Level: OWNER)
 │    ├── Is row in permissions? ──► ALLOW (Level: READ / EDIT)
 │    └── None of above?         ──► 403 FORBIDDEN & Log DENIED attempt
 │
 ├── If AUTHORIZED:
 │    ├── Read encrypted file from /storage/vault_files/
 │    ├── Decrypt buffer via AES-256-GCM (cryptoVault.js)
 │    ├── Verify AuthTag integrity
 │    ├── Append SUCCESS to Audit Blockchain
 │    └── Stream bytes with Content-Disposition attachment
 │
 └── If REJECTED:
      ├── Append DENIED to Audit Blockchain
      └── Return HTTP 403 Forbidden
         │
         ▼
[ Tamper-Evident Audit Blockchain (database.js) ]
 ├── Genesis Block: 64 zeros
 ├── Record: SHA-256(previous_hash + timestamp + actor + action + status + details)
 └── Verification: Sequential recomputation from block 1 to N
```

---

## 🔒 The 3 Non-Negotiable Tenets

### 1. Server Decides Every Time
* Direct URLs like `/uploads/document.pdf` **do not exist**.
* Storage is isolated outside the web directory.
* The critical authorization line:
  ```javascript
  const access = await evaluateAccess(docId, req.user.id);
  if (!access.authorized) return res.status(403).json({ error: 'Access Denied...' });
  ```
  runs synchronously on every single read, download, edit, and delete request.

### 2. Immediate Revocation (0 Millisecond Latency)
* Permissions are stateful rows in the `permissions` table.
* They are **never cached in JWT claims** or client local storage.
* Revoking access deletes the row from SQLite immediately. The very next HTTP request fails with 403.

### 3. Proof of Access & Refusal
* The audit trail records both authorized actions (`SUCCESS`) and blocked attempts (`DENIED`).
* Cryptographic chaining prevents retrospective log alteration.
