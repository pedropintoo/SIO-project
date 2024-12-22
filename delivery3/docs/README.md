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

