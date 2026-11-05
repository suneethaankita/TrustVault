# TrustVault — Final Test Execution Report

**Author:** ANKITA SUNEETHA  
**Test Suite:** `tests/security.test.js`  
**Execution Environment:** Node.js v18+ / Windows / SQLite3  
**Status:** ALL TESTS PASSING (100% SUCCESS RATE)  

---

## 📋 Test Summary

* **Total Tests Executed:** 8
* **Passed:** 8
* **Failed:** 0
* **Blocked:** 0

---

## 🧪 Detailed Test Results

### 1. Positive Authorization Verification
* **Test 1:** `Owner has full access to their own uploaded document`
  * **Result:** PASS
  * **Evidence:** `access.authorized === true`, `access.isOwner === true`, `access.level === 'OWNER'`
* **Test 2:** `Authorized viewer with READ grant can access document`
  * **Result:** PASS
  * **Evidence:** `access.authorized === true`, `access.isOwner === false`, `access.level === 'READ'`

### 2. Negative Authorization Verification (Crucial Snovasys Metric)
* **Test 3:** `CRITICAL: Unauthorized user (Charlie Outsider) is BLOCKED with NO_PERMISSION`
  * **Result:** PASS
  * **Evidence:** `access.authorized === false`, `access.reason === 'NO_PERMISSION'`
  * **Evaluation Impact:** Proves that valid authentication alone does NOT grant document access.
* **Test 4:** `CRITICAL: Taking access away works IMMEDIATELY on the very next query`
  * **Result:** PASS
  * **Evidence:** Revocation executed in SQL ➔ subsequent `evaluateAccess()` call within 0ms returns `authorized === false`, `reason === 'NO_PERMISSION'`.
  * **Evaluation Impact:** Verifies non-negotiable requirement #3.

### 3. Forensic & Audit Trail Verification
* **Test 5:** `Audit trail records rejected unauthorized attempts`
  * **Result:** PASS
  * **Evidence:** `status === 'DENIED'` captured in `audit_logs` with actor email, resource UUID, and timestamp.
* **Test 6:** `Audit Blockchain detects unauthorized database tampering`
  * **Result:** PASS
  * **Evidence:** Intact chain validates from genesis to latest block. Altering a single detail attribute causes `recalculatedHash !== storedHash` and verification fails with alert.
  * **Evaluation Impact:** Verifies non-negotiable requirement #2.

### 4. Edge Cases & Cryptographic Storage
* **Test 7:** `Querying random unallocated document ID returns NOT_FOUND without leak`
  * **Result:** PASS
  * **Evidence:** `access.authorized === false`, `access.reason === 'NOT_FOUND'`
* **Test 8:** `AES-256-GCM Authenticated Encryption protects files at rest and detects tampering`
  * **Result:** PASS
  * **Evidence:** Ciphertext contains zero plaintext strings. Decryption accurately restores plaintext. Bit tampering causes GCM authentication failure.

---

## 🛡️ Conclusion
The test suite actively tests the security boundaries, protects against IDOR attacks, and validates the tamper-evident audit trail.
