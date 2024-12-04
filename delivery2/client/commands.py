import requests
import json
import base64
import os
import sys
from utils import symmetric
from utils.session import send_session_data, encapsulate_session_data, decapsulate_session_data, session_info_from_file
from views.roles import DocumentPermissions
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, InvalidTag

EC_CURVE = ec.SECP256R1()

class Command:
    def __init__(self, logger, state):
        self.logger = logger
        self.state = state
        self.server_address = state['REP_ADDRESS']
        self.server_pub_key = serialization.load_pem_public_key(state['REP_PUB_KEY'].encode(), default_backend())

class Local(Command):
    
    def __init__(self, logger, state):
        super().__init__(logger, state) 
    
    def rep_subject_credentials(self, password, credentials_file):
        
        password_int = int.from_bytes(password.encode(), 'big')

        private_key = ec.derive_private_key(password_int, EC_CURVE, default_backend())

        # Generate the corresponding public key
        public_key = private_key.public_key()

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Store the public key in the credentials file
        with open(credentials_file, 'wb') as f:
            f.write(public_key_bytes)
        
        self.logger.debug(f'Public key stored in credentials file: {credentials_file}')
    
    def rep_decrypt_file(self, encrypted_file, encryption_metadata):
        with open(encryption_metadata, 'r') as f:
            metadata = json.load(f)
        
        key = bytes.fromhex(metadata['key'])
        alg = metadata['alg']
        
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
            
        self.logger.debug(f'{len(encrypted_data)} bytes read from file: {encrypted_data}')
        
        try:
            if alg == 'AES-GCM':
                nonce = encrypted_data[:12]
                ciphertext = encrypted_data[12:]
                decrypted_data = symmetric.decrypt(key, nonce, ciphertext, None)
            else:
                raise Exception(f'Unsupported encryption algorithm: {alg}')
            
        except InvalidTag as e:
            raise Exception(f'Failed to decrypt file: Invalid tag. {e}')
        except Exception as e:
            raise Exception(f'Failed to decrypt file: {e}')
        
        sys.stdout.buffer.write(decrypted_data)
        
class Auth(Command):
    
    def __init__(self, logger, state):
        super().__init__(logger, state)
    
    def rep_create_org(self, organization, username, name, email, public_key_file):
        """This command creates an organization in a Repository and defines its first subject."""
        # POST /api/v1/auth/organization
        pem_data = None
        with open(public_key_file, 'rb') as f:
            pem_data = f.read()
        
        public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
        public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_string = public_key_pem.decode("utf-8")
        
        response = requests.post(f'{self.server_address}/api/v1/auth/organization', json={'organization': organization, 'username': username, 'name': name, 'email': email, 'public_key': public_key_string})
        
        if response.status_code != 200:
            raise Exception(f'[response.status_code] Failed to create organization. Response: {response.text}')
        
        # Get associated data
        associated_data_string = response.json()['associated_data']
        associated_data = json.loads(associated_data_string)
        organization_received = associated_data['organization']
        username_received = associated_data['username']
        name_received = associated_data['name']
        email_received = associated_data['email']
        public_key_received = associated_data['public_key']
        
        signature_hex = response.json()['signature']
        
        # Prevent man-in-the-middle attacks
        if organization_received != organization or username_received != username or name_received != name or email_received != email or public_key_received != public_key_string:
            raise Exception(f'Create organization failed: Invalid organization data')

        try:
            # Verify signature
            self.server_pub_key.verify(
                bytes.fromhex(signature_hex),
                json.dumps(associated_data).encode("utf-8"),
                ec.ECDSA(hashes.SHA256())
            )
            
        except InvalidSignature:
            raise Exception(f'Failed to verify signature')
        
        except Exception as e:
            raise Exception(f'Failed to create organization: {e}')
        
        print(associated_data)

    def rep_create_session(self, organization, username, password, credentials_file, session_file):
        """This command creates a session for a username belonging to an organization, and stores the session context in a file."""
        # POST /api/v1/auth/session
        
        # Client private key from password
        password_int = int.from_bytes(password.encode(), 'big')
        client_private_key = ec.derive_private_key(password_int, EC_CURVE, default_backend())
        
        # Ephemeral key pair
        client_ephemeral_private_key = ec.generate_private_key(EC_CURVE, default_backend())
        client_ephemeral_public_key = client_ephemeral_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_ephemeral_public_key_string = client_ephemeral_public_key.decode("utf-8")
        
        associated_data = {'organization': organization, 'username': username, 'client_ephemeral_public_key': client_ephemeral_public_key_string}
        
        # Sign associated data
        signature = client_private_key.sign(json.dumps(associated_data).encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        signature_hex = signature.hex()
        
        response = requests.post(f'{self.server_address}/api/v1/auth/session', json={'associated_data': associated_data, 'signature': signature_hex})

        if response.status_code != 200:
            raise Exception(f'[response.status_code] Failed to create session. Response: {response.text}')
        
        # Get associated data
        associated_data_string = response.json()['associated_data']
        associated_data = json.loads(associated_data_string)
        signature_hex = response.json()['signature']
        
        try:
            # Verify signature
            self.server_pub_key.verify(
                bytes.fromhex(signature_hex),
                json.dumps(associated_data).encode("utf-8"),
                ec.ECDSA(hashes.SHA256())
            )
        
            # Get server ephemeral public key
            server_ephemeral_public_key_string = associated_data['server_ephemeral_public_key']
            server_ephemeral_public_key_pem = server_ephemeral_public_key_string.encode("utf-8")
            server_ephemeral_public_key = serialization.load_pem_public_key(server_ephemeral_public_key_pem, backend=default_backend())
            
            # Calculate shared key
            shared_key = client_ephemeral_private_key.exchange(ec.ECDH(), server_ephemeral_public_key)
            
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)
            derived_key_hex = derived_key.hex()
            
            # Store session details
            session_id = associated_data['session_id']
            
            with open(session_file, 'w') as f:
                f.write(json.dumps({'session_id': session_id, 'organization': organization, 'username': username, 'derived_key': derived_key_hex, 'msg_id': 0}, indent=4))
                
            self.logger.debug(f'Session created successfully and stored in file {session_file}')

        except InvalidSignature:
            raise Exception(f'Failed to verify signature')
        
        except Exception as e:
            raise Exception(f'Failed to create session: {e}')
        
        print(associated_data)
        
class File(Command):
    
    def ___init__(self, logger, state):
        super().__init__(logger, state)
        
    def rep_get_file(self, file_handle, file=None):
        """This command downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument."""
        # GET /api/v1/files/
        
        response = requests.get(f'{self.server_address}/api/v1/files/', json={'file_handle': file_handle})

        if response.status_code != 200:
            raise Exception(f'[response.status_code] Failed to get file. Response: {response.text}')
        
        # Get associated data
        associated_data_string = response.json()['associated_data']
        associated_data = json.loads(associated_data_string)
        file_handle_received = associated_data['file_handle']
        file_content_string = associated_data['file_content']
        signature_hex = response.json()['signature']
        
        # Prevent man-in-the-middle attacks
        if file_handle_received != file_handle:
            raise Exception(f'Get file failed: Invalid file handle')
        
        file_content = base64.b64decode(file_content_string)

        try:
            # Verify signature
            self.server_pub_key.verify(
                bytes.fromhex(signature_hex),
                json.dumps(associated_data).encode("utf-8"),
                ec.ECDSA(hashes.SHA256())
            )
            
        except InvalidSignature:
            raise Exception(f'Failed to verify signature')
        
        if file:
            with open(file, 'wb') as f:
                f.write(file_content)
        else:
            sys.stdout.buffer.write(file_content)
        
        return file_content
        
class Session(Command):
    
    def __init__(self, logger, state):
        super().__init__(logger, state)

    # ---- Next iteration ---- 
    def rep_assume_role(self, session_file, role):
        """This command requests the given role for the session"""
        # POST /api/v1/sessions/roles
        # requests.post(f'{self.server_address}/api/v1/sessions/roles', json={'session': session, 'role': role})
        
        command = 'post'
        endpoint = '/api/v1/sessions/roles'
        plaintext = {'role': role}

        result = send_session_data(
            self.logger, 
            self.server_address, 
            command,
            endpoint, 
            session_file, 
            plaintext
        )

        print(result)
        
        # Read the existing JSON data
        with open(session_file, 'r') as f:
            data = json.load(f)
        
        # Update the JSON data
        if "role" not in data:
            data["role"] = role
        else:
            if role not in data["role"]:
                if isinstance(data["role"], list):
                    data["role"].append(role)
                else:
                    data["role"] = [data["role"], role]

        # Write the updated data back to the file
        with open(session_file, 'w') as f:
            json.dump(data, f, indent=4)

    # ---- Next iteration ---- 
    def rep_drop_role(self, session_file, role):
        """This command releases the given role for the session"""
        # DELETE /api/v1/sessions/roles
        # requests.delete(f'{self.server_address}/api/v1/sessions/roles', json={'session': session, 'role': role})

        command = 'delete'
        endpoint = '/api/v1/sessions/roles'
        plaintext = {'role': role}

        result = send_session_data(
            self.logger, 
            self.server_address, 
            command,
            endpoint, 
            session_file, 
            plaintext
        )

        print(result)

        # Read the existing JSON data
        with open(session_file, 'r') as f:
            data = json.load(f)

        # Update the JSON data
        if "role" in data:
            if role in data["role"]:
                if isinstance(data["role"], list):
                    data["role"].remove(role)
                else:
                    data["role"] = None

        # Write the updated data back to the file
        with open(session_file, 'w') as f:
            json.dump(data, f, indent=4)

    # ---- Next iteration ---- 
    def rep_list_roles(self, session_file):
        """Lists the current session roles."""
        # GET /api/v1/sessions/roles
        # requests.get(f'{self.server_address}/api/v1/sessions/roles', json={'session': session})
    
    
class Organization(Command):
    
    def __init__(self, logger, state):
        super().__init__(logger, state)
    
    def rep_list_orgs(self):
        """This command lists all organizations defined in a Repository."""
        # GET /api/v1/organizations
        response = requests.get(f'{self.server_address}/api/v1/organizations/')
        
        if response.status_code != 200:
            raise Exception(f'[response.status_code] Failed to list organizations. Response: {response.text}')
        
        organizations = response.json()
        for org in organizations:
            print(org["name"])

    def rep_list_subjects(self, session_file, username=None):
        """This command lists the subjects of the organization with which I have currently a session. The listing should show the state of all the subjects (active or suspended). This command accepts an extra command to show only one subject."""
        # GET /api/v1/organizations/subjects/state

        command = "get"
        endpoint = '/api/v1/organizations/subjects/state'
        plaintext = {'username': username}

        result = send_session_data(
            self.logger, 
            self.server_address, 
            command,
            endpoint, 
            session_file, 
            plaintext
        )
        
        for username, state in result.items():
            print(f'{username}: {state}')

    # ---- Next iteration ----
    def rep_list_role_subjects(self, session_file, role):
        """This command lists the subjects of a role of the organization with which I have currently a session"""
        # GET /api/v1/organizations/roles/<string:role>/subjects
        with open(session, 'rb') as f:
            session = f.read()
        return requests.get(f'{self.server_address}/api/v1/organizations/roles/{role}/subjects', json={'session': session})
    
    # ---- Next iteration ----
    def rep_list_subject_roles(self, session_file, username):
        """This command lists the roles of a subject of the organization with which I have currently a session."""
        # GET /api/v1/organizations/subjects/<string:username>/roles
        return requests.get(f'{self.server_address}/api/v1/organizations/subjects/{username}/roles', json={'session': session})
    
    # ---- Next iteration ----
    def rep_list_role_permissions(self, session_file, role):
        """This command lists the permissions of a role of the organization with which I have currently a session."""
        # GET /api/v1/organizations/roles/<string:role>/permissions
        return requests.get(f'{self.server_address}/api/v1/organizations/roles/{role}/permissions', json={'session': session})

    # ---- Next iteration ----
    def rep_list_permission_roles(self, session_file, permission):
        """This command lists the roles of the organization with which I have currently a session that have a given permission. Use the names previously referred for the permission rights."""
        # GET /api/v1/organizations/permissions/<string:permission>/roles
        return requests.get(f'{self.server_address}/api/v1/organizations/permissions/{permission}/roles', json={'session': session})

    def rep_list_docs(self, session_file, username=None, date=None):
        """This command lists the documents of the organization with which I have currently a session, possibly filtered by a subject that created them and by a date (newer than, older than, equal to), expressed in the DD-MM-YYYY format."""
        # GET /api/v1/organizations/documents
        
        command = 'get'
        endpoint = '/api/v1/organizations/documents'
        date_filter = date[0] if date else None
        date = date[1] if date else None
        plaintext = {'creator': username, 'date_filter': date_filter, 'date_str': date}
        
        result = send_session_data(
            self.logger, 
            self.server_address, 
            command,
            endpoint,
            session_file,
            plaintext
        )
        
        print(result)
        
    def rep_add_subject(self, session_file, username, name, email, credentials_file):
        """This command adds a new subject to the organization with which I have currently a session. By default the subject is created in the active state. This commands requires a SUBJECT_NEW permission."""
        # POST /api/v1/organizations/subjects
        
        pem_data = None
        with open(credentials_file, 'rb') as f:
            pem_data = f.read()
        
        public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
        public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        public_key_string = public_key_pem.decode("utf-8")
        
        command = 'post'
        endpoint = '/api/v1/organizations/subjects'
        plaintext = {'username': username, 'name': name, 'email': email, 'public_key': public_key_string}

        result = send_session_data(
            self.logger, 
            self.server_address, 
            command,
            endpoint,
            session_file,
            plaintext
        )
        
        print(result)
    
    def rep_suspend_subject(self, session_file, username):
        """These commands change the state of a subject in the organization with which I have currently a session. These commands require a SUBJECT_DOWN and SUBJECT_UP permission, respectively."""
        # PUT /api/v1/organizations/subjects/state
        command = 'put'
        endpoint = f'/api/v1/organizations/subjects/state'
        plaintext = {'username': username, 'state': 'suspended'}

        result = send_session_data(
            self.logger,
            self.server_address,
            command,
            endpoint,
            session_file,
            plaintext
        )
        
        print(result)

    def rep_activate_subject(self, session_file, username):
        """These commands change the state of a subject in the organization with which I have currently a session. These commands require a SUBJECT_DOWN and SUBJECT_UP permission, respectively."""
        # PUT /api/v1/organizations/subjects/state
        command = 'put'
        endpoint = f'/api/v1/organizations/subjects/state'
        plaintext = {'username': username, 'state': 'active'}
        
        result = send_session_data(
            self.logger,
            self.server_address,
            command,
            endpoint,
            session_file,
            plaintext
        )
        
        print(result)

    # ---- Next iteration ----
    def rep_add_role(self, session_file, role):
        """This command adds a role to the organization with which I have currently a session. This commands requires a ROLE_NEW permission."""
        # POST /api/v1/organizations/roles
        return requests.post(f'{self.server_address}/api/v1/organizations/roles', json={'session': session, 'role': role})

    # ---- Next iteration ----
    def rep_suspend_role(self, session_file, role):
        """These commands change the state of a role in the organization with which I have currently a session. These commands require a ROLE_DOWN and ROLE_UP permission, respectively."""
        # PUT /api/v1/organizations/roles/<string:role>/state
        return requests.put(f'{self.server_address}/api/v1/organizations/roles/{role}/state', json={'session': session})

    # ---- Next iteration ----
    def rep_reactivate_role(self, session_file, role):
        """These commands change the state of a role in the organization with which I have currently a session. These commands require a ROLE_DOWN and ROLE_UP permission, respectively."""
        # PUT /api/v1/organizations/roles/<string:role>/state
        return requests.put(f'{self.server_address}/api/v1/organizations/roles/{role}/state', json={'session': session})

    # ---- Next iteration ----
    def rep_add_permission(self, session_file, role, permissionOrUsername):
        """These commands change the properties of a role in the organization with which I have currently a session, by adding a subject, removing a subject, adding a permission or removing a permission, respectively. Use the names previously referred for the permission rights. These commands require a ROLE_MOD permission."""
        # POST /api/v1/organizations/roles/<string:role>/permissions
        # POST /api/v1/organizations/roles/<string:role>/subjects
        if permissionOrUsername in DocumentPermissions.values():
            return requests.post(f'{self.server_address}/api/v1/organizations/roles/{role}/permissions', json={'session': session, 'permission': permissionOrUsername})
        else:
            return requests.post(f'{self.server_address}/api/v1/organizations/roles/{role}/subjects', json={'session': session, 'username': permissionOrUsername})

    # ---- Next iteration ----
    def rep_remove_permission(self, session_file, role, permissionOrUsername):
        """These commands change the properties of a role in the organization with which I have currently a session, by adding a subject, removing a subject, adding a permission or removing a permission, respectively. Use the names previously referred for the permission rights. These commands require a ROLE_MOD permission."""
        # POST /api/v1/organizations/roles/<string:role>/permissions
        # POST /api/v1/organizations/roles/<string:role>/subjects
        if permissionOrUsername in DocumentPermissions.values():
            return requests.delete(f'{self.server_address}/api/v1/organizations/roles/{role}/permissions', json={'session': session, 'permission': permissionOrUsername})
        else:
            return requests.delete(f'{self.server_address}/api/v1/organizations/roles/{role}/subjects', json={'session': session, 'username': permissionOrUsername})

    def rep_add_doc(self, session_file, document_name, file):
        """This command adds a document with a given name to the organization with which I have currently a session. The document’s contents is provided as parameter with a file name. This commands requires a DOC_NEW permission."""
        # POST /api/v1/organizations/documents
        with open(file, 'rb') as f:
            file_content = f.read()
        
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(file_content)
        file_handle_hex = digest.finalize().hex()
        
        key = os.urandom(32)
        alg = 'AES-GCM'
        nonce, ciphertext = symmetric.encrypt(key, file_content, None)
        encrypted_file = base64.b64encode(nonce + ciphertext).decode("utf-8")
        
        command = 'post'
        endpoint = '/api/v1/organizations/documents'
        plaintext = {
            'encryption_file': encrypted_file,
            'document_acl': {}, # TODO: check this
            'file_handle': file_handle_hex,
            'name': document_name,
            'key': key.hex(),
            'alg': alg
        }
        
        result = send_session_data(
            self.logger, 
            self.server_address, 
            command,
            endpoint,
            session_file,
            plaintext
        )
        
        print(result)

    def rep_get_doc_metadata(self, session_file, document_name):
        """This command fetches the metadata of a document with a given name to the organization with which I have currently a session. The output of this command is useful for getting the clear text contents of a document’s file. This commands requires a DOC_READ permission."""
        # GET /api/v1/organizations/documents/metadata
        command = 'get'
        endpoint = f'/api/v1/organizations/documents/metadata'
        plaintext = {'document_name': document_name}
        
        result = send_session_data(
            self.logger, 
            self.server_address, 
            command,
            endpoint,
            session_file,
            plaintext
        )

        print(result)

        return result
        
    def rep_get_doc_file(self, session_file, document_name, file=None):
        """This command is a combination of rep_get_doc_metadata with rep_get_file and rep_decrypt_file. The file contents are written to stdout or to the file referred in the optional last argument. This commands requires a DOC_READ permission."""
       
        metadata = self.rep_get_doc_metadata(session_file, document_name)
        file_handle = metadata['file_handle'] 
        file_obj = File(self.logger, self.state)
        encrypted_data = file_obj.rep_get_file(file_handle)
        key = bytes.fromhex(metadata['key'])
        alg = metadata['alg'] 
        
        # clear buffer
        sys.stdout.flush()

        try:
            if alg == 'AES-GCM':
                nonce = encrypted_data[:12]
                ciphertext = encrypted_data[12:]
                file_content = symmetric.decrypt(key, nonce, ciphertext, None)
            else:
                raise Exception(f'Unsupported encryption algorithm: {alg}')
            
        except InvalidTag:
            raise Exception(f'Failed to decrypt file: Invalid tag')
        
        except Exception as e:
            raise Exception(f'Failed to decrypt file: {e}')

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(file_content)
        file_handle_verify = digest.finalize().hex()
        
        if file_handle_verify != file_handle:
            raise Exception(f'Failed to verify file handle')
        
        if file:
            with open(file, 'wb') as f:
                f.write(file_content)
        else:
            sys.stdout.buffer.write(file_content)
        
    def rep_delete_doc(self, session_file, document_name):
        """This command clears file_handle in the metadata of a document with a given name on the organization with which I have currently a session. The output of this command is the file_handle that ceased to exist in the document’s metadata. This commands requires a DOC_DELETE permission."""
        # DELETE /api/v1/organizations/documents/
        command = 'delete'
        endpoint = f'/api/v1/organizations/documents/'
        plaintext = {'document_name': document_name}
        
        result = send_session_data(
            self.logger,
            self.server_address,
            command,
            endpoint,
            session_file,
            plaintext
        )
        print(result)
        return result
    
    # ---- Next iteration ----
    def rep_acl_doc(self, session_file, document_name, operation, role, permission):
        """This command changes the ACL of a document by adding (+) or removing (-) a permission for a given role. Use the names previously referred for the permission rights. This commands requires a DOC_ACL permission."""
        # GET /api/v1/organizations/documents/<string:document_name>/acl
        return requests.get(f'{self.server_address}/api/v1/organizations/documents/{document_name}/acl', json={'session': session, 'operation': operation, 'role': role, 'permission': permission})
