I have used "https://planttext.com/" to create the sequential diagrams.


### Create Session

```mermaid
@startuml
hide footbox
actor Client
participant Repository

Client -> Client: Generate ephemeral keys (ECDH)
Client -> Client: Sign associated_data (ECDSA + SHA-256)
Client -> Repository: Send associated_data + signature
Repository -> Repository: Verify signature
Repository -> Repository: Generate ephemeral keys (ECDH)
Repository -> Repository: Calculate shared_key (ECDH)
Repository -> Repository: Derive derived_key (HKDF)
Repository -> Client: Send session_id + repository ephemeral key (signed)
Client -> Client: Verify repository signature
Client -> Client: Calculate shared_key (ECDH)
Client -> Client: Derive derived_key (HKDF)
Client -> Client: Store session details
@enduml
```

### Create Organization

```mermaid
@startuml
hide footbox

actor Client
participant Repository

Client -> Repository: Send POST /api/v1/auth/organization\nwith organization, username, name,\nemail, and public_key
Repository -> Repository: Validate request fields\n(organization, username, name, email, public_key)
Repository -> Repository: Check if organization exists\n(using in_database method)
alt Organization exists
    Repository -> Client: Return error "Organization already exists"
else Organization does not exist
    Repository -> Repository: Create organization object\n- Add first subject (username)\n- Assign Managers role with permissions\n- Initialize documents metadata
    Repository -> Repository: Insert organization object into database
    Repository -> Repository: Derive private key (secret_key)\nusing MASTER_KEY and ECC
    Repository -> Repository: Prepare associated_data\n(organization, username, name, email, public_key)
    Repository -> Repository: Sign associated_data\n(using ECDSA and SHA-256)
    Repository -> Client: Return associated_data and signature
end
Client -> Client: Compare received data\nwith original request for integrity
Client -> Client: Verify server's signature\n(using server's public key)
Client -> Client: Output associated_data

@enduml
```

### Communicating with the Repository

```mermaid
@startuml
hide footbox
actor Client
participant Repository

Client -> Repository : GET /api/v1/files/ with file_handle
activate Repository

Repository -> Repository : Locate file using file_handle
Repository -> Repository : Read file content
Repository -> Repository : Encode file content to Base64

Repository -> Repository : Prepare associated_data\n(file_handle, file_content)
Repository -> Repository : Sign associated_data\nusing private key (ECDSA + SHA-256)
Repository -> Client : Return associated_data and signature
deactivate Repository

activate Client
Client -> Client : Compare received file_handle\nwith original
alt File handle matches
    Client -> Client : Verify signature using\nserver's public key
    alt Signature valid
        Client -> Client : Decode file content from Base64
        Client -> Client : Save to file or write to stdout
    else Invalid signature
        Client -> Client : Raise error (Signature verification failed)
    end
else File handle mismatch
    Client -> Client : Raise error (Invalid file handle)
end
deactivate Client
@enduml
```

### Assume a role

@startuml
hide footbox

actor Client
participant Repository

== Request to Assume Role ==

Client -> Client: Read session_file (session ID, derived_key, msg_id)
Client -> Client: Increment msg_id to prevent replay attacks
Client -> Client: Encapsulate data with\nAES-GCM (role, msg_id, session ID)
Client -> Repository: POST /api/v1/sessions/roles (encapsulated data)

== Processing on Repository ==

Repository -> Repository: Decapsulate data with\nAES-GCM (validate msg_id, session ID)
Repository -> Repository: Verify user is active
Repository -> Repository: Check if user has the role
alt Role exists
    Repository -> Repository: Add role to session (avoid duplicates)
    Repository -> Repository: Prepare success response
else Role does not exist
    Repository -> Repository: Prepare error response
end
Repository -> Repository: Encapsulate response with\nAES-GCM (response, updated msg_id)

== Response to Client ==

Repository -> Client: Send encapsulated response

== Client Response Handling ==

Client -> Client: Decapsulate response with\nAES-GCM (validate msg_id, session ID)
Client -> Client: Check if msg_id <= session_file msg_id
alt Replay attack detected
    Client -> Client: Raise Exception (Replay attack)
else Valid msg_id
    Client -> Client: Update session_file with new msg_id
    Client -> Client: Verify HTTP status code
    alt Status code != 200
        Client -> Client: Raise Exception (Command failed)
    else Status code == 200
        Client -> Client: Update local session data (add role if not present)
    end
end

@enduml



### Add Subject

```mermaid
@startuml
hide footbox

actor Client
participant Repository

== Request to Add a Subject ==
Client -> Client: Read public key from file
Client -> Client: Prepare plaintext with username, name, email, and public key
Client -> Client: Encapsulate data with AES-GCM
Client -> Repository: Send POST /api/v1/organizations/subjects with encapsulated data

== Processing on Repository ==
Repository -> Repository: Decapsulate request with AES-GCM
Repository -> Repository: Validate `msg_id` and `session_id`
Repository -> Repository: Check if user is active
alt User inactive
    Repository -> Client: Return error (403: User not active)
else User active
    Repository -> Repository: Check `SUBJECT_NEW` permission
    alt User lacks permission
        Repository -> Client: Return error (403: Missing permission)
    else User has permission
        Repository -> Repository: Check if username exists in database
        alt Username exists
            Repository -> Client: Return error (409: Subject already exists)
        else Username does not exist
            Repository -> Repository: Add subject to database
            Repository -> Repository: Prepare success response
        end
    end
end
Repository -> Repository: Encapsulate response with AES-GCM

== Response to Client ==
Repository -> Client: Send response with encapsulated data

== Client Response Handling ==
Client -> Client: Decapsulate response with AES-GCM
Client -> Client: Validate `msg_id` to prevent replay attacks
alt Replay attack detected
    Client -> Client: Raise exception (Replay attack)
else No replay attack
    Client -> Client: Check status code
    alt Success
        Client -> Client: Confirm subject added
    else Failure
        Client -> Client: Raise exception with error
    end
end
Client -> Client: Update session file with new `msg_id`

@enduml
```
