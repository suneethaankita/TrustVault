# TrustVault — Interview Walkthrough & Live Viva Preparation
**Candidate:** Ankita Suneetha  
**For:** Snovasys Technical Interview & Live Code Walkthrough  

---

## 🎯 The Single Most Important Question You WILL Be Asked

> **Question:** "Where is the authorization decision made when someone downloads a file, and what would happen if that line were removed?"

### Your Answer (English):
> "The authorization decision is made in **`controllers/documentController.js`** inside the **`downloadDocument`** function at line 140:
> ```javascript
> const access = await evaluateAccess(docId, req.user.id);
> if (!access.authorized) {
>   // logs denied attempt and returns 403 Forbidden
>   return res.status(403).json({ error: 'Access Denied...' });
> }
> ```
> Inside `evaluateAccess()`, the server executes a direct synchronous SQL query against the database to check if the user is either the original document owner or has an active row in the `permissions` table.
> 
> **What happens if that line is removed?**  
> If that check is removed, the system suffers a catastrophic **Insecure Direct Object Reference (IDOR)** vulnerability. Any authenticated user (or attacker) who knows or guesses a document's UUID could download confidential files belonging to other departments, because the server would proceed straight to `fs.createReadStream().pipe(res)` without verifying if that user was ever granted permission. Furthermore, unauthorized download attempts would no longer be detected or logged in the audit trail."

### Same Answer in Easy Telugu / Tenglish (Ardham cheskodaniki):
> "Mana project lo `controllers/documentController.js` file lo `downloadDocument` function untundi. Andulo:
> `const access = await evaluateAccess(docId, req.user.id);`
> ane line daggara authorization decision jarugutundi. 
> 
> Server direct ga database ki velli, ee user ki ee document meeda permission unda leda ani live ga check chestundi.
> 
> **Aa line theesthe em avtundi?**
> Aa line theesesinappudu, IDOR (Insecure Direct Object Reference) ane pedda security hole create avtundi. Evaraina vere user document ID thelsukoni direct ga URL lo kottina sare, server check cheyakunda file pampisthundi. And audit trail lo denied attempt log avvadu."

---

## 🎯 Question 2: "How does 'Taking access away immediately' work in your architecture?"

### Answer:
> "We intentionally chose **stateful database authorization** instead of baking permissions into stateless JWT claims.
> 
> In traditional systems where permissions are put inside JWT tokens, if an owner revokes access, the user can still use their unexpired token for hours.
> 
> In TrustVault, when an owner clicks 'Revoke Access', our API immediately runs:
> ```sql
> DELETE FROM permissions WHERE document_id = ? AND user_id = ?;
> ```
> Since every single download request queries the `permissions` table dynamically, the access termination takes effect in **0 milliseconds** — the very next HTTP request from that user is blocked with HTTP 403."

---

## 🎯 Question 3: "How is your Audit Trail protected against tampering?"

### Answer:
> "Our audit trail uses **Cryptographic SHA-256 Hash Chaining (a blockchain model)** implemented in `database.js`.
> 
> For each log entry, we compute:
> `entry_hash = SHA-256(previous_hash + timestamp + actor + action + status + details)`.
> 
> The first record begins with 64 zeros. Every subsequent log is mathematically linked to the previous one. 
> 
> If anyone (even a rogue database administrator) changes a single letter in an old log or deletes a row to hide evidence, the hash chain breaks. Our `/api/audit/verify` endpoint checks the entire chain sequentially and will immediately highlight the exact record that was altered."

---

## 🎯 Question 4: "Where are files stored and why can't someone open them directly in a browser?"

### Answer:
> "Files are stored in `/storage/vault_files/` which is located **outside the public web root**. 
> 
> 1. We deliberately do NOT use `express.static` on the storage directory, so direct URLs like `/uploads/file.pdf` return 404.
> 2. Files on disk are renamed to random cryptographic UUIDs (`crypto.randomUUID()`) to prevent path traversal attacks.
> 3. Bytes are only sent to the client through an authenticated Node.js stream after `evaluateAccess()` succeeds."
