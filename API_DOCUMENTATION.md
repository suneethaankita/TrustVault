# TrustVault — REST API Reference & Authorization Matrix

This document provides complete documentation for every endpoint in TrustVault, specifying HTTP methods, authentication requirements, role authorization, request/response bodies, and status codes.

---

## 🔐 Authorization Key

* **Public (Rate Limited):** Accessible without authentication.
* **Authenticated:** Requires a valid session token (Cookie or Bearer).
* **Owner:** Requires the authenticated user to be the original creator (`owner_id === req.user.id`).
* **Admin:** Requires `role === 'ADMIN'`.
* **Granted User:** Requires an active record in `permissions` for the target document.

---

## 1. Authentication Endpoints

### `POST /api/auth/register`
* **Access:** Public (Rate limited: 20 req / 15 min)
* **Request Body:**
  ```json
  {
    "name": "Jane Doe",
    "email": "jane@example.com",
    "password": "Password123!",
    "role": "OWNER"
  }
  ```
* **Success Response:** `201 Created`
  ```json
  {
    "message": "Account created successfully. You can now sign in.",
    "userId": "uuid-v4"
  }
  ```
* **Error Responses:**
  * `400 Bad Request`: Missing required fields or password under 8 characters.
  * `409 Conflict`: Email already registered.

### `POST /api/auth/login`
* **Access:** Public (Rate limited: 20 req / 15 min)
* **Request Body:**
  ```json
  {
    "email": "owner@trustvault.com",
    "password": "Password123!"
  }
  ```
* **Success Response:** `200 OK` (Sets HTTP-only cookie `trustvault_token`)
  ```json
  {
    "message": "Sign in successful.",
    "token": "jwt-token-string",
    "user": {
      "id": "uuid-v4",
      "name": "Alice Document Owner",
      "email": "owner@trustvault.com",
      "role": "OWNER"
    }
  }
  ```
* **Error Response:** `401 Unauthorized` (Logs `LOGIN_FAILURE` in audit blockchain).

### `GET /api/auth/me`
* **Access:** Authenticated
* **Success Response:** `200 OK` with user profile.

### `POST /api/auth/logout`
* **Access:** Authenticated
* **Success Response:** `200 OK` (Clears session cookie, logs `LOGOUT`).

### `GET /api/auth/users`
* **Access:** Authenticated
* **Success Response:** `200 OK` with list of users for permission assignment.

---

## 2. Document Management Endpoints

### `POST /api/documents/upload`
* **Access:** Authenticated (`OWNER` or `ADMIN`)
* **Content-Type:** `multipart/form-data`
* **Payload:**
  * `document`: File binary (Max 10MB; Whitelist: `.pdf`, `.docx`, `.txt`, `.png`, `.jpg`, `.csv`, `.xlsx`)
  * `title`: String (Required)
  * `category`: String (Optional, e.g. "Financial", "Legal")
* **Success Response:** `201 Created`
  ```json
  {
    "message": "Document uploaded and securely encrypted on disk.",
    "documentId": "uuid-v4"
  }
  ```
* **Security:** File is renamed to random UUID, encrypted with AES-256-GCM, and stored outside public web directory.

### `GET /api/documents`
* **Access:** Authenticated
* **Query Parameters:** `search`, `category`, `ownerEmail`, `startDate`, `endDate`
* **Success Response:** `200 OK`
  ```json
  {
    "documents": [
      {
        "id": "uuid-v4",
        "title": "Executive Salary Letter 2026",
        "original_filename": "Executive_Salary_2026.txt",
        "mime_type": "text/plain",
        "file_size": 256,
        "category": "Financial",
        "owner_name": "Alice Document Owner",
        "owner_email": "owner@trustvault.com",
        "my_permission": "OWNER"
      }
    ]
  }
  ```
* **Security:** Queries are strictly scoped to `(d.owner_id = user.id OR p.user_id = user.id)`. Unauthorized documents are invisible.

### `GET /api/documents/:id/download`
* **Access:** `OWNER` or Granted User (`READ` or `EDIT`)
* **Success Response:** `200 OK` (Binary file stream with `Content-Disposition: attachment`)
* **Security:** Runs `evaluateAccess()`. If unauthorized, logs `UNAUTHORIZED_DOWNLOAD_ATTEMPT` with `status: DENIED` and returns `403 Forbidden`.

### `GET /api/documents/:id/preview`
* **Access:** `OWNER` or Granted User (`READ` or `EDIT`)
* **Success Response:** `200 OK` with in-memory decrypted text or base64 data URL.
* **Error Response:** `403 Forbidden` if unauthorized.

### `PUT /api/documents/:id`
* **Access:** `OWNER` or Granted User (`EDIT`)
* **Request Body:** `{"title": "Updated Title", "category": "Legal"}`
* **Success Response:** `200 OK`

### `DELETE /api/documents/:id`
* **Access:** `OWNER` strictly
* **Success Response:** `200 OK` (Deletes DB record, cascades permissions, and securely unlinks encrypted file).

---

## 3. Permissions Management Endpoints

### `POST /api/documents/:id/permissions`
* **Access:** `OWNER` strictly
* **Request Body:**
  ```json
  {
    "targetUserId": "recipient-uuid-v4",
    "permissionLevel": "READ"
  }
  ```
* **Success Response:** `200 OK`

### `DELETE /api/documents/:id/permissions/:userId`
* **Access:** `OWNER` strictly
* **Description:** Immediate Access Revocation.
* **Success Response:** `200 OK` (Access terminates instantly for next query).

### `GET /api/documents/:id/permissions`
* **Access:** `OWNER` strictly
* **Success Response:** `200 OK` with active permission grants.

---

## 4. Audit Trail Endpoints

### `GET /api/audit`
* **Access:** `ADMIN` strictly
* **Query Parameters:** `status` (`SUCCESS` or `DENIED`), `action`, `actorEmail`, `limit`
* **Success Response:** `200 OK` with global audit trail.

### `GET /api/audit/verify`
* **Access:** `ADMIN` strictly
* **Success Response:** `200 OK`
  ```json
  {
    "verified": true,
    "message": "Audit trail cryptographic verification passed. All records are intact, strictly sequential, and tamper-free.",
    "totalRecordsVerified": 42,
    "latestChainHash": "sha256-hash"
  }
  ```
* **Tamper Response:** `400 Bad Request` with `compromisedAtId` and explanation if any row was edited or removed.

### `GET /api/audit/document/:id`
* **Access:** `OWNER` of target document or `ADMIN`
* **Success Response:** `200 OK` with full activity timeline for that specific document.
