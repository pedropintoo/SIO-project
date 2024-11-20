# Delivery 1

## Group members
- 113893 - Guilherme Santos
- 104383 - João Pinto
- 115304 - Pedro Pinto

## Structure
 - `client/` - contains the client side code
 - `server/` - contains the server side code
 - `views/` - contains the classes for the views


## Features Implemented

### Local commands

#### Creating public key for a subject
The command `rep_subject_credentials` generates a public key for the user by the derivation of a private key from his password using `ECC`.

#### Decrypt a file
The command `rep_decrypt_file`, decrypts an encrypted file while ensuring its integrity using the specified encryption metadata. The metadata includes the encryption algorithm (alg) and key (key). If successful, the decrypted contents are written to stdout.

### Commands that use the anonymous API
In commands that use the anonymous API, `rep_create_org`, `rep_create_session` and `rep_get_file`, the server will return the desired data signed by a **secret_key** derived from it's **private key** (`MASTER_KEY`) so the subject can garante **authenticity** and **integrity** of the data received.

In the command `rep_list_org` we did not implement this step because we didn't see a potential benefit of a possible attack to this command since the organizations' information is public. 

#### Create an organization
The command `rep_create_org` creates an organization by sending the required information to the server. From the server side, it will create the organization in the mongo database and return the associated data from the organization for validation. 

#### List all organizations
The command `rep_list_orgs` lists all organizations defined in a Repository.

#### Create a Session
The command `rep_create_session` function securely establishes a user session by deriving a private key from the password, performing an elliptic curve key exchange, and verifying server responses. It sends signed session data to the server, computes a shared key using ECDH, derives an encryption key with HKDF, and stores the session ID, derived key, and context in a file for future use. Errors, such as invalid signatures or failed requests, are logged.

#### Download a File
The command `rep_get_file` downloads a file by giving it's `file_handle` to the server. Then, the server will return the encrypted file by searching in it's **vault** of files where each file is named with it's `file_handle`.

### Commands that use the Authenticated and Authorized API
Because for this delivery we didn't implement role based sessions, the following explanation is valid for both API's endpoints:

Each communication to the server using any of the endpoints requires a session

- The client creates a `plaintext` with the relevant information that he wants to send;
- 

### Authenticated API

#### List Subjects
The command `rep_list_subjects` lists all subjects in the organisation associated with the current session, displaying their statuses (active or suspended). It optionally accepts a specific username to filter the results. The function sends a GET request with session data to the `/api/v1/organizations/subjects/state` endpoint and prints the returned usernames and their statuses.

#### List documents
The command `rep_list_docs` lists documents from the organisation associated with the current session, allowing optional filtering by creator and date. The date filter can specify documents newer than, older than, or equal to a given date in the DD-MM-YYYY format. It sends a GET request with the specified filters to the `/api/v1/organizations/documents` endpoint and prints the returned document list.

### Authorized API

#### Add subject
The rep_add_subject function adds a new subject to the organisation associated with the current session. By default, the subject is created in an active state and requires the SUBJECT_NEW permission. The function reads a public key from a credentials file, converts it to a PEM-encoded string, and sends a POST request with the subject's details (username, name, email, and public key) to the /api/v1/organizations/subjects endpoint. On the server side, the endpoint validates the session, increments the session's message ID, and stores the subject details in the organisation database.



