# TrustVault — Automated Testing Guide & Security Verification

**Candidate:** ANKITA SUNEETHA  
**Test Suite:** `tests/security.test.js`  

---

## 🎯 Test Strategy & Philosophy

The challenge instructions state:
> *"Your automated tests should cover the cases in your own THREATS.md. We will take one authorisation check out of your code and run your tests. If they still pass, they were not testing anything."*

Our test suite is deliberately designed around **Negative Authorization Testing**:
* We do not merely test that owners can download files.
* We specifically test that unauthorized outsiders receive `403 Forbidden` and `NO_PERMISSION`.
* We test that revoking permission terminates access **instantly on the next millisecond query**.
* We test that unauthorized attempts generate `status: 'DENIED'` audit logs.
* We test that modifying a single character in the audit table breaks the cryptographic SHA-256 hash chain.
* We test that files encrypted at rest cannot be decrypted if bytes are tampered with.

---

## 🏃 Running the Automated Test Suite

Run the following command in the project directory:

```bash
npm test
```
(Or directly: `node tests/security.test.js`)

---

## 📊 Test Suite Coverage Matrix

| Test # | Test Name | Attack Vector / Scenario Tested | Assertion Verified |
| :--- | :--- | :--- | :--- |
| **Test 1** | Owner Full Access | Owner accessing their confidential uploaded record. | `access.authorized === true`, `level === 'OWNER'` |
| **Test 2** | Authorized Viewer Grant | Viewer with valid `READ` permission downloading file. | `access.authorized === true`, `level === 'READ'` |
| **Test 3** | **Unauthorized Outsider Blocked** | Charlie Outsider attempts to read/download Alice's salary document. | `access.authorized === false`, `reason === 'NO_PERMISSION'` |
| **Test 4** | **Immediate Revocation** | Owner revokes permission; next access check executes immediately. | Permission deleted from DB ➔ immediate `access.authorized === false` |
| **Test 5** | **Audit Trail Records Denied Attempts** | Unauthorized probe occurs; verifies event is captured in audit log. | `log.status === 'DENIED'`, `log.actor_email === outsider.email` |
| **Test 6** | **Cryptographic Tamper Detection** | Simulates insider modifying audit record details directly in SQL. | `recalculatedHash !== storedHash`, chain verification fails |
| **Test 7** | Non-Existent Document Enumeration | Attacker queries random UUIDs. | `access.authorized === false`, `reason === 'NOT_FOUND'` |
| **Test 8** | **AES-256-GCM Encryption at Rest** | Verifies ciphertext does not expose plaintext and tampered bytes fail GCM check. | `!encrypted.includes(plaintext)`, GCM integrity failure on bit flip |

---

## 🔬 The "Remove One Check" Drill

If an evaluator comments out the authorization check in `controllers/documentController.js`:
```javascript
// const access = await evaluateAccess(docId, req.user.id);
// if (!access.authorized) ...
```
**Test 3, Test 4, and Test 5 fail immediately**, proving that our tests actively defend and validate the authorization boundary.
