# PROMPTS.md — AI Interaction & Vulnerability Catch Log
**Author:** Ankita Suneetha  
**Challenge:** Snovasys Fresher Hiring Challenge 2026 (RISE)  
**System:** TrustVault — Secure Document Sharing with a Real Audit Trail  

---

## Overview
This log documents key prompts provided to AI tools during the development of TrustVault, the specific security vulnerabilities or architectural flaws identified in the AI's generated code, and the corrective engineering decisions applied.

As required by the marking rubric, multiple entries focus specifically on **authorization, access control, and audit trail integrity**.

---

### Entry 1 (2026-11-02) — Storing Permissions inside JWT Claims (Authorization Flaw)
- **Prompt:**  
  *"Generate a JWT authentication and authorization middleware for Express where users can download documents based on their permissions."*
- **What the AI Produced:**  
  The AI encoded user permissions directly into the JWT token payload at login time:
  ```javascript
  // AI Generated code
  const token = jwt.sign({ id: user.id, email: user.email, permissions: ['READ_DOC_123', 'EDIT_DOC_456'] }, JWT_SECRET, { expiresIn: '24h' });
  ```
- **What Was Wrong With It Specifically:**  
  **Violates the non-negotiable requirement: "Taking access away works immediately."**  
  If user permissions are baked into a JWT claim with a 24-hour expiration, revoking a user's access in the database has **zero effect** until the JWT expires or is rotated. The revoked user could continue downloading confidential documents for up to 24 hours using their existing token.
- **What We Did Instead:**  
  We stripped all permission data from the JWT. The token now strictly represents identity (`userId`). We created the `evaluateAccess(docId, userId)` engine in `controllers/documentController.js` that performs a **live, synchronous database query against SQLite on every single download request**. When an owner revokes access, the permission row is deleted, and the very next HTTP request within 1 millisecond fails with HTTP `403 Forbidden`.
- **Commit Reference:** `commit a17f8b9 (fix: enforce stateful database-tier permission checks for immediate revocation)`

---

### Entry 2 (2026-11-03) — Static Serving of Uploaded Files (Direct URL Bypass)
- **Prompt:**  
  *"Configure file upload handling with Multer and serve uploaded files in Express."*
- **What the AI Produced:**  
  The AI configured Multer to save files in `public/uploads` and added static file middleware:
  ```javascript
  // AI Generated code
  app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));
  ```
- **What Was Wrong With It Specifically:**  
  **Total bypass of all authorization checks.**  
  By serving the uploads directory statically through `express.static`, anyone with the direct URL (or who intercepted network traffic, checked browser cache, or guessed filenames) could download confidential documents directly from `https://domain.com/uploads/document.pdf` without logging in, without headers, and without passing any authorization code.
- **What We Did Instead:**  
  1. Relocated the storage vault to `/storage/vault_files/`, located completely **outside the public web root**.
  2. Removed any `express.static` serving for storage.
  3. Implemented `/api/documents/:id/download`, which enforces `evaluateAccess()` and streams the file using `fs.createReadStream().pipe(res)`. There is no direct web route to files.
- **Commit Reference:** `commit c492d11 (security: isolate storage directory and route all file reads through dynamic auth controller)`

---

### Entry 3 (2026-11-04) — Mutable Plaintext Audit Logging (Audit Tampering Flaw)
- **Prompt:**  
  *"Create an audit log table in SQLite and an API to record document downloads and views."*
- **What the AI Produced:**  
  The AI generated a standard table:
  ```sql
  CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    action TEXT,
    timestamp TEXT
  );
  ```
  And an endpoint that simply inserted rows.
- **What Was Wrong With It Specifically:**  
  **Violates the non-negotiable requirement: "An audit trail that can be quietly altered is not evidence, and we will ask you what stops that."**  
  Plain SQL records can be easily modified, updated, or deleted by anyone with database access (or through SQL injection) without leaving a trace. There was no mechanism to mathematically prove whether an entry had been tampered with or removed. Additionally, it did not record **DENIED attempts**, only successful ones!
- **What We Did Instead:**  
  1. Built a **Cryptographic SHA-256 Hash Chained Audit Blockchain** in `database.js`. Each log entry calculates:
     `entry_hash = SHA-256(previous_hash + timestamp + actor_email + action + resource_id + status + details)`.
  2. Added an `/api/audit/verify` verification engine that iterates through the chain from genesis and detects any single bit modification or missing row.
  3. Explicitly recorded `status = 'DENIED'` on all unauthorized access attempts so auditors can detect penetration attempts.
- **Commit Reference:** `commit e82a034 (feat: implement SHA-256 hash-chained tamper-evident audit trail with integrity verification)`

---

### Entry 4 (2026-11-05) — Preserving Original User Filenames (Path Traversal Risk)
- **Prompt:**  
  *"Set up Multer diskStorage to save uploaded files with their original filenames."*
- **What the AI Produced:**  
  ```javascript
  // AI Generated code
  const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
      cb(null, file.originalname);
    }
  });
  ```
- **What Was Wrong With It Specifically:**  
  1. **Path Traversal vulnerability**: A maliciously crafted filename like `../../server.js` or `..\..\..\etc\cron` could overwrite server code.
  2. **Collision & Overwrite**: If two users uploaded `Resume.pdf`, one user would silently overwrite the other's file.
  3. **Information Leakage**: Filenames visible in server logs or filesystem.
- **What We Did Instead:**  
  Configured Multer to generate a cryptographically random UUID v4 for the stored file (`${crypto.randomUUID()}${ext}`). The user's original filename is sanitized and stored only as a display label in the database metadata.
- **Commit Reference:** `commit f31b5c8 (fix: prevent path traversal and file collision using UUID disk names)`

---

### Entry 5 (2026-11-06) — Information Leakage in Document Search API
- **Prompt:**  
  *"Write a search endpoint to filter documents by title, category, and date."*
- **What the AI Produced:**  
  ```javascript
  // AI Generated code
  app.get('/api/documents', async (req, res) => {
    const docs = await db.all('SELECT * FROM documents WHERE title LIKE ?', [`%${req.query.search}%`]);
    res.json(docs);
  });
  ```
- **What Was Wrong With It Specifically:**  
  **Metadata & confidentiality leakage.**  
  While the AI checked permissions when downloading a file, it completely forgot to filter search results by user access! Any user searching for "Salary" or "Confidential" could see the list of all confidential documents in the entire company, who uploaded them, and when, even if they had no permission to read them.
- **What We Did Instead:**  
  Restricted the search query to join `permissions` and filter:
  `WHERE (d.owner_id = ? OR p.user_id = ?)`  
  Users can strictly only discover and search documents they own or have been explicitly granted permission to access.
- **Commit Reference:** `commit 9a4e217 (security: scope document search query strictly to authorized user grants)`

---

### Entry 6 (2026-11-05) — Helmet CSP Directive Blocking Inline Event Handlers (`script-src-attr`)
- **Prompt:**  
  *"Add Helmet security headers with Content Security Policy to secure TrustVault against XSS and clickjacking."*
- **What the AI Produced:**  
  The AI configured Helmet CSP with:
  ```javascript
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"]
      }
    }
  })
  ```
- **What Was Wrong With It Specifically:**  
  **Application broke in production browsers with 42 CSP errors.**  
  In modern Helmet (v7+), the Content Security Policy defaults `script-src-attr: 'none'` unless explicitly overridden. Even though `'unsafe-inline'` was in `scriptSrc`, the browser blocked all `onclick` event handlers on buttons (role switching, file downloads, modals) with the console error:  
  `Executing inline event handler violates the following Content Security Policy directive 'script-src-attr 'none''`.
- **What We Did Instead:**  
  Configured `scriptSrcAttr: ["'unsafe-inline'"]` inside Helmet's CSP directives, allowing button event handlers to execute securely while maintaining strict origin boundaries (`defaultSrc: ["'self'"]`).
- **Commit Reference:** `commit (fix(security): configure helmet scriptSrcAttr to permit UI event handlers while maintaining CSP origin bounds)`

---

## Reusable System Prompt Used Across the Week
Whenever prompting AI tools during this project, we enforced this standardized context prompt:

```text
You are an expert security engineer reviewing code for TrustVault, a zero-trust enterprise document platform.
Non-negotiable rules:
1. Every file access must evaluate dynamic authorization at the database level on every request (no caching of permissions).
2. All denied attempts must be logged to a tamper-evident audit trail with cryptographic hash chaining.
3. Storage must be isolated outside web root; no static file serving.
4. User input (IDs, filenames, search queries) must never be trusted.
Highlight all potential bypasses before writing any implementation.
```
