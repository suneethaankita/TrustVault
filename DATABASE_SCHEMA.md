# TrustVault — Relational Database Schema & Data Dictionary

**Engine:** SQLite 3 (Production Compatible with PostgreSQL)  
**ORM / Driver:** `sqlite3` driver with Promise-wrapped query interfaces  
**File:** `trustvault.db` (Configurable via `DB_PATH`)  

---

## 🗄️ Entity-Relationship Model

```text
       ┌───────────────┐
       │     USERS     │
       └───────┬───────┘
               │ 1
               │
               ├─────────────────────────┐
               │ 1:N                     │ 1:N
               ▼                         ▼
       ┌───────────────┐         ┌──────────────────────┐
       │   DOCUMENTS   │ 1       │     PERMISSIONS      │
       └───────┬───────┘         └──────────────────────┘
               │                          ▲
               │ 1:N                      │
               └──────────────────────────┘
                         N (FK document_id)

       ┌────────────────────────┐
       │       AUDIT_LOGS       │ (Append-Only Cryptographic Blockchain)
       └────────────────────────┘
```

---

## 📋 Table Specifications

### 1. `users`
Stores user identities, credentials, and system-level roles.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | TEXT | PRIMARY KEY | Cryptographically generated UUID v4. |
| `name` | TEXT | NOT NULL | User's full display name. |
| `email` | TEXT | UNIQUE, NOT NULL | Normalized lowercase email address. |
| `password_hash`| TEXT | NOT NULL | One-way salted hash generated using bcrypt (cost factor = 10). |
| `role` | TEXT | NOT NULL, CHECK(`ADMIN`, `OWNER`, `VIEWER`) | System role determining administrative access. |
| `created_at` | TEXT | NOT NULL | ISO 8601 UTC timestamp. |

---

### 2. `documents`
Stores document metadata. Physical binary files are stored encrypted on disk, NOT as BLOBs, to prevent database bloating.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | TEXT | PRIMARY KEY | Cryptographically generated UUID v4. |
| `title` | TEXT | NOT NULL | Human-readable document title. |
| `original_filename` | TEXT | NOT NULL | Original sanitized name supplied during upload. |
| `stored_filename` | TEXT | NOT NULL | Random UUID filename on disk (`${UUID}${ext}`). Prevents path traversal. |
| `mime_type` | TEXT | NOT NULL | Validated MIME type (e.g. `application/pdf`, `text/plain`). |
| `file_size` | INTEGER | NOT NULL | File size in bytes. |
| `category` | TEXT | NOT NULL | Classification category (Financial, Legal, Engineering, General). |
| `owner_id` | TEXT | NOT NULL, FK(`users.id`) ON DELETE CASCADE | Original uploader who possesses sole administrative control. |
| `created_at` | TEXT | NOT NULL | ISO 8601 UTC timestamp. |
| `updated_at` | TEXT | NOT NULL | ISO 8601 UTC timestamp of last metadata modification. |

---

### 3. `permissions`
Direct per-document access grants assigned to named user accounts.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | TEXT | PRIMARY KEY | Cryptographically generated UUID v4. |
| `document_id` | TEXT | NOT NULL, FK(`documents.id`) ON DELETE CASCADE | Target document. |
| `user_id` | TEXT | NOT NULL, FK(`users.id`) ON DELETE CASCADE | Recipient user identity. |
| `permission_level` | TEXT | NOT NULL, CHECK(`READ`, `EDIT`) | `READ`: Download/Preview. `EDIT`: Metadata updates. |
| `granted_by` | TEXT | NOT NULL, FK(`users.id`) | Owner who authorized this grant. |
| `granted_at` | TEXT | NOT NULL | ISO 8601 UTC timestamp. |
| **Index** | UNIQUE | `UNIQUE(document_id, user_id)` | Prevents duplicate permission grants. |

---

### 4. `audit_logs`
Append-only, immutable tamper-evident log linking each entry cryptographically to its predecessor.

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Sequential ledger block number. |
| `timestamp` | TEXT | NOT NULL | ISO 8601 UTC timestamp of event. |
| `actor_id` | TEXT | NULLABLE | User UUID who initiated request (NULL if unauthenticated visitor). |
| `actor_name` | TEXT | NOT NULL | User name or 'Anonymous'. |
| `actor_email` | TEXT | NOT NULL | User email or 'anonymous@trustvault.local'. |
| `action` | TEXT | NOT NULL | Standardized action slug (e.g. `DOCUMENT_DOWNLOAD`, `UNAUTHORIZED_DOWNLOAD_ATTEMPT`). |
| `resource_type` | TEXT | NOT NULL | `DOCUMENT`, `PERMISSION`, `AUTH`, `USER`, `SYSTEM`. |
| `resource_id` | TEXT | NULLABLE | Target UUID (e.g. document UUID). |
| `resource_name` | TEXT | NULLABLE | Display name of target resource. |
| `status` | TEXT | NOT NULL, CHECK(`SUCCESS`, `DENIED`) | Whether the operation was authorized or blocked. |
| `ip_address` | TEXT | NULLABLE | Client remote IP address resolved via proxy trust. |
| `user_agent` | TEXT | NULLABLE | Client browser User-Agent header string. |
| `details` | TEXT | NULLABLE | Detailed operational narrative and refusal reason. |
| `previous_hash` | TEXT | NOT NULL | SHA-256 hash of previous block (Genesis = 64 zeros). |
| `entry_hash` | TEXT | NOT NULL | SHA-256 hash over previous_hash and current entry attributes. |

---

## 🔒 Immutability Guarantees

* **Zero Update/Delete Endpoints:** There is no route or controller in the application that performs `UPDATE` or `DELETE` on the `audit_logs` table.
* **Foreign Key Constraints:** Cascade deletes clean up orphaned documents and permissions when an account is deleted, while audit logs retain historical actor UUIDs to preserve forensic evidence.
