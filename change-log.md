## Changes Made for the Supplementary Season

**Delivery 1:**
- We added argument validation to the following commands: `rep_create_session`, `rep_suspend_subject`, `rep_add_doc`, `rep_get_doc_metadata`, `rep_get_doc_file`, `rep_delete_doc`.
- Added JSON output to `rep_get_doc_metadata` and `rep_delete_doc`.
- Eliminated unintentional replay attack errors. That is, when a bug occurs, the `msg_id` is not incremented.

**Delivery 2:**
- Made two improvements:
  - Ensured that Managers can never be suspended.
  - Guaranteed that users **cannot assume suspended roles**.

**Delivery 3:**
- **Revisions and enhancements have been made to the following chapters:**
  - [A] - File Confidentiality Model
  - [B] - Access Control
  - [C] - Data Model for Organizations, Subjects, Roles, Metadata e Files
  - [D] - Subject Management

