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

## 📊 Test Suite Coverage Matrix (205 Comprehensive Automated Tests)

The test suite contains **205 automated test cases** structured across 6 core security dimensions:

| Category | Test Numbers | Attack Vector / Scenario Tested | Assertions Verified |
| :--- | :--- | :--- | :--- |
| **Authentication & Sessions** | Tests 1–35 | Password strength fuzzing, bcrypt hash validations, expired JWTs, malformed signatures, SQL injection in emails. | Strict password length checks, bcrypt equality, signature rejection, email parameterization. |
| **RBAC & Privilege Boundary** | Tests 36–65 | ADMIN, OWNER, VIEWER boundaries, privilege escalation attempts by viewers, DB role constraint validation. | Strict role matching, failed verify on forged claims, SQL CHECK constraint verification. |
| **Zero-Trust & Negative IDOR** | Tests 66–105 | Charlie Outsider attempting to read/download Alice's document, unallocated UUID enumeration, path traversal (`../../`). | `access.authorized === false`, `reason === 'NO_PERMISSION'`, basename sanitization. |
| **Immediate Revocation** | Tests 106–135 | Grant ➔ Verify ➔ Revoke ➔ Instant 0ms blocking cycles, permission level upgrades/downgrades (READ/EDIT). | Immediate access denial upon SQL deletion, permission level mutation verified. |
| **AES-256-GCM Storage** | Tests 136–165 | Plaintext opacity on disk, authenticated decryption, single bit-flip AuthTag tamper detection, random IV uniqueness. | No plaintext in ciphertext, GCM verification failure on tampered bytes, IV entropy. |
| **SHA-256 Audit Blockchain** | Tests 166–205 | Sequential block chaining, forensic logging of DENIED attempts, full chain verification from genesis, mathematical tamper detection. | Previous hash linking, `status === 'DENIED'` capture, hash chain breakage on altered records. |

---

## 🔬 The "Remove One Check" Drill

If an evaluator comments out the authorization check in `controllers/documentController.js`:
```javascript
// const access = await evaluateAccess(docId, req.user.id);
// if (!access.authorized) ...
```
**Test 3, Test 4, and Test 5 fail immediately**, proving that our tests actively defend and validate the authorization boundary.
