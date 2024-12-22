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