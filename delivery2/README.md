# Delivery 2

## Group members
- 113893 - Guilherme Santos
- 104383 - João Pinto
- 115304 - Pedro Pinto

We mantained the same structure as in the previous delivery.

## Features Implemented

### Commands that use the authenticated API

#### Assume a role
The command `rep_assume_role` enables a user to assume a specific role within the organisation associated with the current session. It sends a POST request containing the desired role to the `/api/v1/sessions/roles` endpoint, ensuring the data's integrity and confidentiality by encrypting it with AES-GCM. Upon receiving the request, the server validates the session, verifies the user's active status, and checks whether the user has the specified role within the organisation. If authorised, the server updates the session to reflect the assumed role and responds with a confirmation message. On the client side, the session file is updated to include the new role, allowing the user to seamlessly operate with the assumed role in subsequent commands. If the user is not authorised for the role, the server returns an appropriate error message.

#### Drop a role
The command `rep_drop_role` allows a user to release a previously assumed role within the organisation associated with the current session. It sends a DELETE request with the specified role to the `/api/v1/sessions/roles` endpoint, ensuring data integrity and confidentiality using AES-GCM encryption. On the server side, the session is validated, the user's active status is verified, and the existence of the role within the current session is checked. If the user holds the role, it is removed from the session, and a success message is returned. On the client side, the session file is updated to reflect the removal of the role, maintaining consistency between the client and server. If the user does not hold the role, an error message is provided, ensuring proper handling of unauthorised actions.

#### List Roles
The command `rep_list_roles` retrieves and displays the roles currently associated with the session. It sends a GET request to the `/api/v1/sessions/roles` endpoint, ensuring data integrity and confidentiality through AES-GCM encryption. On the server side, the session is validated, and the user's active status is verified. The server then retrieves the list of roles stored in the session and returns this information encapsulated in an encrypted response. The client decapsulates the server’s response and prints the list of roles.

#### List Role Subjects
The command `rep_list_role_subjects` retrieves the list of subjects associated with a specific role in the organisation linked to the current session. It sends a GET request to the `/api/v1/organizations/roles/subjects` endpoint with the role name included in the encrypted payload.

On the server side, the session is validated, the user's active status is checked, and the subjects associated with the specified role are retrieved from the organisation's database. If the role does not exist, an appropriate error message is returned. The client decapsulates the server's response and displays the list of subjects along with their statuses..

#### List Subject Roles
The command `rep_list_subject_roles` retrieves the roles assigned to a specified subject within the organisation associated with the current session. It sends a GET request to the `/api/v1/organizations/subjects/roles` endpoint, including the target subject's username in the encrypted payload. On the server side, the session is validated, and the user's active status is confirmed. The server then retrieves the roles associated with the specified subject from the organisation's database. The response is encrypted and sent back to the client, which decapsulates the data and prints the list of roles assigned to the subject.
In the case of a subject not found, the server returns an appropriate error message.

#### List Role Permissions
The command `rep_list_role_permissions` retrieves the permissions associated with a specified role in the organisation linked to the current session. It sends a GET request to the `/api/v1/organizations/roles/permissions` endpoint, including the role's name in the encrypted payload. The server validates the session and ensures the user's active status. It then queries the organisation's database to retrieve the permissions assigned to the specified role. If the role exists, the permissions are encapsulated and returned in an encrypted response. The client decapsulates the response and displays the permissions with their statuses. If the role does not exist, an appropriate error message is returned.

#### List Permission Roles
The command `rep_list_permission_roles` retrieves the roles within the organisation associated with the current session that have been granted a specified permission. It sends a GET request to the `/api/v1/organizations/permissions/roles` endpoint, including the permission name in the encrypted payload. On the server side, the session is validated, the user's active status is confirmed, and the organisation's database is queried to identify roles that have the specified permission. Additionally, the server examines the permissions in the documents' Access Control Lists (ACLs) and lists roles per document that have the specified permission, distinguishing between document-specific permissions and general organisation permissions. The roles are encapsulated in the server's response, which is decrypted and displayed by the client. If the permission does not exist, an appropriate error message is returned.

#### Add Role
The command `rep_add_role` adds a new role to the organisation associated with the current session. This operation requires the user to have the `ROLE_NEW` permission. The command sends a POST request to the `/api/v1/organizations/roles` endpoint with the role name encapsulated in the encrypted payload. On the server side, the session is validated, the user's active status is confirmed, and the required `ROLE_NEW` permission is checked. If authorised, the server creates a new role in the organisation's database with default attributes such as an active state, no associated subjects, and no assigned permissions. If the role already exists, an error message is returned. The client decrypts the server’s response and displays the outcome.

#### Suspend Role
The command `rep_suspend_role` suspends a specified role within the organisation associated with the current session. This operation requires the user to have the `ROLE_DOWN` permission. The command sends a PUT request to the `/api/v1/organizations/roles/suspend` endpoint with the role name encapsulated in the encrypted payload. On the server side, the session is validated, the user's active status is confirmed, and the required `ROLE_DOWN` permission is checked. If authorised, the server updates the role's state to "suspended" in the organisation's database. If the specified role does not exist, an error message is returned. The client decapsulates the server's response to display whether the role was successfully suspended or if an error occurred.

#### Reactivate Role
The command `rep_reactivate_role` reactivates a specified role within the organisation associated with the current session. This operation requires the user to have the `ROLE_UP` permission. The command sends a PUT request to the `/api/v1/organizations/roles/reactivate` endpoint with the role name encapsulated in the encrypted payload. On the server side, the session is validated, the user's active status is confirmed, and the required `ROLE_UP` permission is checked. If authorised, the server updates the role's state to "active" in the organisation's database. If the specified role does not exist, an error message is returned. The client decapsulates the server's response to confirm whether the role was successfully reactivated or if an error occurred.

#### Add Permission or Subject to Role
The command `rep_add_permission` modifies the properties of a role in the organisation associated with the current session by adding either a permission or a subject. The specific operation is determined based on the `permissionOrUsername` parameter. If a permission is provided, the command sends a POST request to the `/api/v1/organizations/roles/permissions` endpoint; if a username is provided, it targets the `/api/v1/organizations/roles/subjects` endpoint. Both operations require the user to hold the `ROLE_MOD` permission.

On the server side, the session is validated, the user's active status is confirmed, and the required `ROLE_MOD` permission is checked. For permission additions, the server updates the role's permissions list, ensuring the permission does not already exist. For subject additions, the username is added to the role's subjects list, preventing duplicates. The client decapsulates the server's response and display the outcome of the operation.

#### Remove Permission or Subject from Role
The command `rep_remove_permission` removes a specified permission or subject from a role in the organisation associated with the current session. It sends a DELETE request to either the `/api/v1/organizations/roles/permissions` or `/api/v1/organizations/roles/subjects` endpoint. This operation requires the `ROLE_MOD` permission.

The server validates the session, checks authorisation, and updates the role's permissions or subjects list. The client displays the server's response.

#### Update Document ACL
The command `rep_acl_doc` modifies the Access Control List (ACL) of a document by either adding (`+`) or removing (`-`) a permission for a specified role. It sends a POST request to the `/api/v1/organizations/documents/acl` endpoint with the document name, operation, role, and permission as part of the encrypted payload. This operation requires the user to hold the `DOC_ACL` permission.

On the server side, the session is validated, the user's active status is confirmed, and the required `DOC_ACL` permission for the specified document is checked. If the operation is `+`, the server adds the permission to the document's ACL for the given role. If the operation is `-`, the server removes the specified permission. For invalid operations or non-existent roles, permissions, or documents, an appropriate error message is returned.

The client decapsulates the server's response and displays the outcome of the operation.