# TrustVault — Known Limitations & Deliberate Design Decisions

Honesty about architectural scope and conscious trade-offs is a core criterion in the Snovasys evaluation rubric:
> *"Tell us what you chose not to build, and why. A smaller system with a permission model that holds beats a larger one with a hole in it. Saying plainly that something is unfinished costs you very little. Saying it works when it does not ends your application."*

---

## 1. Consciously Accepted Limitations

### A. Flat Explicit Grants vs. Complex Folder Hierarchy
* **What is Not Built:** Nested folders with inherited permissions.
* **Why:** The problem statement specifically highlighted that enterprise document leaks occur when *"Someone is given access to a folder so they can see one file, and they can now see forty."* Permission inheritance trees inevitably create accidental privilege widening. We deliberately chose direct, per-document explicit grants to keep authorization clear and mathematically auditable.

### B. Single Master Key vs. Per-Document KMS Envelope Encryption
* **What is Built:** AES-256-GCM encryption at rest using a server-derived master key.
* **Limitation:** All files on a single instance share the derived vault encryption key rather than using individual per-file KMS data keys (envelope encryption).
* **Mitigation:** The encryption key is isolated in memory and never written to the client. In an enterprise production roadmap, integrating AWS KMS or HashiCorp Vault is the natural next step.

### C. In-Memory Preview Support
* **What is Supported:** Direct in-browser modal preview is supported for text files (`.txt`, `.csv`) and images (`.png`, `.jpg`).
* **Limitation:** Complex binary formats (`.pdf`, `.docx`, `.xlsx`) cannot be rendered directly in the custom modal and require the authorized user to click "Download File". This avoids pulling in heavy, vulnerability-prone client-side PDF rendering libraries (e.g. vulnerable versions of PDF.js).

### D. Centralized Audit Log Verification
* **What is Built:** Cryptographic SHA-256 hash chaining within the relational database.
* **Limitation:** While the hash chain detects any retrospective row editing or deletion, if the entire database file were restored from a prior snapshot, an external witness would be needed to prove the rollback.
* **Future Enhancement:** Anchoring periodic chain heads (e.g., daily root hash) to an immutable public ledger (such as RFC 6962 Certificate Transparency logs or a public blockchain).
