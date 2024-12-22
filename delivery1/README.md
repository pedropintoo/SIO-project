# Delivery 1

## Group members
- 113893 - Guilherme Santos
- 104383 - João Pinto
- 115304 - Pedro Pinto

## Structure
 - `client/` - contains the client side code
 - `server/` - contains the server side code
 - `views/` - contains the classes for the views

In this work, we utilised MongoDB as the primary database to manage organisational data, including documents, metadata, and user information. 

## How to run the code

Server:
```bash
docker compose up --build
```

Client:
```bash
python3 subject.py <command> <args>
```

Tests:
```bash
cd commands
./test_features_1
```


## Features Implemented

### Local commands

#### Creating public key for a subject
The command `rep_subject_credentials` generates a public key for the user by the derivation of a private key from his password using `ECC`.

#### Decrypt a file
The command `rep_decrypt_file`, decrypts an encrypted file while ensuring its integrity using the specified encryption metadata. The metadata includes the encryption algorithm (alg) and key (key). If successful, the decrypted contents are written to stdout.

---

### Commands that use the anonymous API
In commands that use the anonymous API, `rep_create_org`, `rep_create_session` and `rep_get_file`, the server will return the desired data signed by a **secret_key** derived from it's **private key** (`MASTER_KEY`) so the subject can garante **authenticity** and **integrity** of the data received.

In the command `rep_list_org` we did not implement this step because we didn't see a potential benefit of a possible attack to this command since the organizations' information is public. 

#### Create an organization
The command `rep_create_org` creates an organization by sending the required information to the server. From the server side, it will create the organization in the mongo database and return the associated data from the organization for validation. 

#### List all organizations
The command `rep_list_orgs` lists all organizations defined in a Repository.

#### Create a Session
The command `rep_create_session` function securely establishes a client session by generating an ephemeral private key from the clients's private key (derived from the password) and an ephemeral public key.

Then it wraps the `associated_data` with the `organization`, `username`, `client_ephemeral_public_key` and sign this data with it's private key using **ECDSA** and **SHA256** then sends this associated_data and the `signature` to the server.

The server verifies the signature by using the client's public key and then generates it's own ephemeral private and public keys that it will be used to perform a **ECDH** key change by generating a `shared_key` from it's ephemeral private key and the client's ephemeral public key. From this shared key is derived a `derived_key` with **HKDF** to add a second layer of protection to the key.

Then the servers add the session information to it's sessions and send the session id and it's `ephemeral_public_key` signed with it's private key

The client then verifies the signature of the associated data and generates the shared key and it's derived key using the `server_ephemeral_public_key` and, finally, writes the session information in a `session_file`.

#### Download a File
The command `rep_get_file` downloads a file by giving it's `file_handle` to the server. Then, the server will return the encrypted file by searching in it's **vault** of files where each file is named with it's `file_handle`.

---

### Commands that use the Authenticated and Authorized API
Because for this delivery we didn't implement role based sessions, the following explanation is valid for both API's endpoints:

Each communication to the server using any of the endpoints requires a session

- The client creates a `plaintext` with the relevant information that he wants to send;
- The client loads the `session file` and updates it's `msg_id` to prevent **replay attacks**;
- Then encapsulates the session data by grouping the `msg_id` and the `session_id` in the `associated_data` and encrypting the `plaintext` and the `associated_data` with the `derived_key` to a `encryption_data`;
- Then it sends the `encryption_data` and the `associated_data` to the endpoint;
- Then encapsulates the session data by grouping the `msg_id` and the `session_id` in the `associated_data` and encrypting the `plaintext` and the `associated_data` with the `derived_key` to a `encryption_data` using **AESGCM** to also add **integrity** to the message;
- It get the session by the `session_id` in the sessions and checks the current `msg_id` for **replay attacks**;
- Then gets the session details like the organization, username and the derived key and decrypts resulting in the plain_text sended by the user;
- Then it updates the `msg_id`, make all the operations needed and build up a new encapsulated data and the message take the inverse path to the user;
- Finally, the user decapsulates/decrypts the message received from the server. 
\
### Authenticated API

#### List Subjects
The command `rep_list_subjects` lists all subjects in the organisation associated with the current session, displaying their statuses (active or suspended). It optionally accepts a specific username to filter the results. The function sends a GET request with session data to the `/api/v1/organizations/subjects/state` endpoint and prints the returned usernames and their statuses.

#### List documents
The command `rep_list_docs` lists documents from the organisation associated with the current session, allowing optional filtering by creator and date. The date filter can specify documents newer than, older than, or equal to a given date in the DD-MM-YYYY format. It sends a GET request with the specified filters to the `/api/v1/organizations/documents` endpoint and prints the returned document list.

### Authorized API

#### Add subject
The command `rep_add_subject` function adds a new subject to the organisation associated with the current session. By default, the subject is created in an active state. The function reads a public key from a credentials file, converts it to a PEM-encoded string, and sends a POST request with the subject's details (username, name, email, and public key) to the `/api/v1/organizations/subjects` endpoint. On the server side, the endpoint validates the session, increments the session's message ID, and stores the subject details in the organisation database.

#### Suspend and Activate subject
The commands `rep_suspend_subject` and `rep_activate_subject` change the status of a subject in the organization with which I have currently a session.

#### Add Document
The command `rep_add_doc` securely adds a document to the organisation associated with the current session. The client reads the document file, computes a unique file handle using a SHA-256 digest, and encrypts the file content with AES-GCM using a randomly generated 256-bit key. The encrypted file, its metadata (file handle, encryption key, algorithm, and access control list), and the document name are sent to the server. On the server, the session is validated, the document's integrity is verified using the file handle, and the encryption key is securely re-encrypted using a derived master key. The server stores the document metadata in the database, writes the encrypted file to disk, and responds with a success message encapsulated in the session context.

#### Get Document Metadata
The command `rep_get_doc_metadata` retrieves the metadata of a specified document within the organisation associated with the current session. The client sends a GET request with the document name to the `/api/v1/organizations/documents/metadata` endpoint. The server validates the session and retrieves the document's metadata, including sensitive details like the encryption key, file handle, and algorithm. The encryption key, securely stored in an encrypted form, is decrypted using a derived master key generated with PBKDF2 and a salt stored alongside the metadata. Public metadata properties, such as the document's name, creation date, creator, and access control list, are returned to the client, along with the decrypted encryption key, for use in decrypting the document’s contents.

#### Get Document File
The command `rep_get_doc_file` combines the functionality of retrieving document metadata, downloading the encrypted file, and decrypting its contents. It fetches the document metadata using `rep_get_doc_metadata`, retrieves the encrypted file using its handle via `rep_get_file`, and decrypts the file content using the encryption key and algorithm provided in the metadata. The decrypted file content is either written to the specified output file or sent to stdout. It performs integrity verification by comparing the SHA-256 digest of the decrypted content with the file handle.

#### Delete Document 
The command `rep_delete_doc` clears the file_handle from the metadata of a specified document in the organisation associated with the current session, effectively "soft-deleting" the document. The client sends a DELETE request with the document's name to the server, which verifies the session and fetches the document's metadata. The server then performs a soft delete by setting the file_handle to None and adding the deleter field to indicate who performed the deletion. The response includes the file_handle that was removed, along with encryption details. 



