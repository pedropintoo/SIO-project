# Server Key Management

1. **Authentication Key Pair**:
   - A static key pair (public/private) used only for authentication, not for encrypting sessions.
   - This pair is long-lived and allows the client to verify the server's identity. The server’s public authentication key can be shared with clients and does not change often.

2. **Ephemeral Session Key Pair**:
   - A new key pair (public/private) generated for each session to ensure forward secrecy.
   - This pair is short-lived, used specifically for encrypting a single session. It changes with each session, meaning each session has a unique shared key that cannot be reused.
   - Once the session is complete, this ephemeral key pair is discarded.


# Server database

## Filesystem

  - organizations: [
        {
            "org1":{ 
                subjects: [
                    "user1": {
                        full_name: "User full name",
                        email: "user email"   
                        public_key: "132131231231"
                    },
                    ...             
                ]
                roles: [
                    "Managers": {
                        
                ]
            }
        }                         
    ]






