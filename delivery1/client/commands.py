import requests
from views.roles import DocumentPermissions
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib
import json

EC_CURVE = ec.SECP256R1()

class Command:
    def __init__(self, logger, state):
        self.logger = logger
        self.state = state
        self.server_address = state['REP_ADDRESS']
        self.server_pub_key = state['REP_PUB_KEY']

class Local(Command):
    
    def __init__(self, logger, state):
        super().__init__(logger, state) 
    
    def rep_subject_credentials(self, password, credentials_file):
        
        password_int = int.from_bytes(password.encode(), 'big')

        private_key = ec.derive_private_key(password_int, EC_CURVE, default_backend())
        self.logger.debug(f'Private key created successfully') 

        # Generate the corresponding public key
        public_key = private_key.public_key()
        self.logger.debug(f'Public key created successfully')

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Store the public key in the credentials file
        with open(credentials_file, 'wb') as f:
            f.write(public_key_bytes)
        self.logger.debug(f'Public key stored in credentials file: {credentials_file}')
    
    def rep_decrypt_file(self, encrypted_file, encryption_metadata):
        self.logger.debug(f"Encryption metadata: {encryption_metadata}")
        algorithm = self.state[encryption_metadata]['algorithm']
        key = self.state[encryption_metadata]['key']
        # TODO: ...
        

class Auth(Command):
    
    def __init__(self, logger, state):
        super().__init__(logger, state)
    
    
    def rep_create_org(self, organization, username, name, email, public_key_file):
        """This command creates an organization in a Repository and defines its first subject."""
        # POST /api/v1/auth/organization
        pem_data = None
        with open(public_key_file, 'rb') as f:
            pem_data = f.read()
        
        if pem_data is None:
            self.logger.error(f'Failed to read public key file: {public_key_file}')
            return -1
        
        public_key = serialization.load_pem_public_key(pem_data, None).public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        
        self.logger.debug(f'Starting organization creation with public key: {public_key}')
        requests.post(f'{self.server_address}/api/v1/auth/organization', json={'organization': organization, 'username': username, 'name': name, 'email': email, 'public_key': public_key})
        self.logger.info(f'Organization {organization} created successfully')

    def rep_create_session(self, organization, username, password, credentials_file, session_file):
        """This command creates a session for a username belonging to an organization, and stores the session context in a file."""
        # POST /api/v1/auth/session
        session_public_key = None
        with open(credentials_file, 'r') as f:
            session_public_key = f.read()
        
        response = requests.post(f'{self.server_address}/api/v1/auth/session', json={'organization': organization, 'username': username, 'password': password, 'session_public_key': session_public_key})

        self.logger.debug(response.json())

class File(Command):
    
    def ___init__(self, logger, state):
        super().__init__(logger, state)
        
    def rep_get_file(self, file_handle, file=None):
        """This command downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument."""
        # GET /api/v1/files/<string:file_handle>
        return requests.get(f'{self.server_address}/api/v1/files/{file_handle}')  

class Session(Command):
    
    def __init__(self, logger, state):
        super().__init__(logger, state)

    # ---- Next iteration ---- 
    def rep_assume_role(self, session_file, role):
        """This command requests the given role for the session"""
        # POST /api/v1/sessions/roles
        return requests.post(f'{self.server_address}/api/v1/sessions/roles', json={'session_file': session_file, 'role': role})

    # ---- Next iteration ---- 
    def rep_drop_role(self, session_file, role):
        """This command releases the given role for the session"""
        # DELETE /api/v1/sessions/roles
        return requests.delete(f'{self.server_address}/api/v1/sessions/roles', json={'session_file': session_file, 'role': role})
    
    # ---- Next iteration ---- 
    def rep_list_roles(self, session_file):
        """Lists the current session roles."""
        # GET /api/v1/sessions/roles
        return requests.get(f'{self.server_address}/api/v1/sessions/roles', json={'session_file': session_file})
    
    
class Organization(Command):
    
    def __init__(self, logger, state):
        super().__init__(logger, state)
    
    def rep_list_orgs(self):
        """This command lists all organizations defined in a Repository."""
        # GET /api/v1/organizations
        response = requests.get(f'{self.server_address}/api/v1/organizations/')
        if response.status_code == 200:
            organizations = response.json()
            print(organizations)
        else:
            self.logger.error(f'Failed to list organizations: {response.status_code}')

    def rep_list_subjects(self, session_file, username=None):
        """This command lists the subjects of the organization with which I have currently a session. The listing should show the status of all the subjects (active or suspended). This command accepts an extra command to show only one subject."""
        # GET /api/v1/organizations/subjects/<string:username>/status
        # GET /api/v1/organizations/subjects/status
        if username:
            return requests.get(f'{self.server_address}/api/v1/organizations/subjects/{username}/status', json={'session_file': session_file})
        else:
            return requests.get(f'{self.server_address}/api/v1/organizations/subjects/status', json={'session_file': session_file})

    # ---- Next iteration ----
    def rep_list_role_subjects(self, session_file, role):
        """This command lists the subjects of a role of the organization with which I have currently a session"""
        # GET /api/v1/organizations/roles/<string:role>/subjects
        with open(session_file, 'rb') as f:
            session = f.read()
        return requests.get(f'{self.server_address}/api/v1/organizations/roles/{role}/subjects', json={'session': session})
    
    # ---- Next iteration ----
    def rep_list_subject_roles(self, session_file, username):
        """This command lists the roles of a subject of the organization with which I have currently a session."""
        # GET /api/v1/organizations/subjects/<string:username>/roles
        return requests.get(f'{self.server_address}/api/v1/organizations/subjects/{username}/roles', json={'session_file': session_file})
    
    # ---- Next iteration ----
    def rep_list_role_permissions(self, session_file, role):
        """This command lists the permissions of a role of the organization with which I have currently a session."""
        # GET /api/v1/organizations/roles/<string:role>/permissions
        return requests.get(f'{self.server_address}/api/v1/organizations/roles/{role}/permissions', json={'session_file': session_file})

    # ---- Next iteration ----
    def rep_list_permission_roles(self, session_file, permission):
        """This command lists the roles of the organization with which I have currently a session that have a given permission. Use the names previously referred for the permission rights."""
        # GET /api/v1/organizations/permissions/<string:permission>/roles
        return requests.get(f'{self.server_address}/api/v1/organizations/permissions/{permission}/roles', json={'session_file': session_file})

    def rep_list_docs(self, session_file, username=None, date_filter=None, date=None):
        """This command lists the documents of the organization with which I have currently a session, possibly filtered by a subject that created them and by a date (newer than, older than, equal to), expressed in the DD-MM-YYYY format."""
        # GET /api/v1/organizations/documents
        return requests.get(f'{self.server_address}/api/v1/organizations/documents', json={'session_file': session_file, 'username': username, 'date_filter': date_filter, 'date': date})

    def rep_add_subject(self, session_file, username, name, email, credentials_file):
        """This command adds a new subject to the organization with which I have currently a session. By default the subject is created in the active status. This commands requires a SUBJECT_NEW permission."""
        # POST /api/v1/organizations/subjects
        return requests.post(f'{self.server_address}/api/v1/organizations/subjects', json={'session_file': session_file, 'username': username, 'name': name, 'email': email, 'credentials_file': credentials_file})

    def rep_suspend_subject(self, session_file, username):
        """These commands change the status of a subject in the organization with which I have currently a session. These commands require a SUBJECT_DOWN and SUBJECT_UP permission, respectively."""
        # PUT /api/v1/organizations/subjects/<string:username>/status
        return requests.put(f'{self.server_address}/api/v1/organizations/subjects/{username}/status', json={'session_file': session_file})

    def rep_activate_subject(self, session_file, username):
        """These commands change the status of a subject in the organization with which I have currently a session. These commands require a SUBJECT_DOWN and SUBJECT_UP permission, respectively."""
        # PUT /api/v1/organizations/subjects/<string:username>/status
        return requests.put(f'{self.server_address}/api/v1/organizations/subjects/{username}/status', json={'session_file': session_file})

    # ---- Next iteration ----
    def rep_add_role(self, session_file, role):
        """This command adds a role to the organization with which I have currently a session. This commands requires a ROLE_NEW permission."""
        # POST /api/v1/organizations/roles
        return requests.post(f'{self.server_address}/api/v1/organizations/roles', json={'session_file': session_file, 'role': role})

    # ---- Next iteration ----
    def rep_suspend_role(self, session_file, role):
        """These commands change the status of a role in the organization with which I have currently a session. These commands require a ROLE_DOWN and ROLE_UP permission, respectively."""
        # PUT /api/v1/organizations/roles/<string:role>/status
        return requests.put(f'{self.server_address}/api/v1/organizations/roles/{role}/status', json={'session_file': session_file})

    # ---- Next iteration ----
    def rep_reactivate_role(self, session_file, role):
        """These commands change the status of a role in the organization with which I have currently a session. These commands require a ROLE_DOWN and ROLE_UP permission, respectively."""
        # PUT /api/v1/organizations/roles/<string:role>/status
        return requests.put(f'{self.server_address}/api/v1/organizations/roles/{role}/status', json={'session_file': session_file})

    # ---- Next iteration ----
    def rep_add_permission(self, session_file, role, permissionOrUsername):
        """These commands change the properties of a role in the organization with which I have currently a session, by adding a subject, removing a subject, adding a permission or removing a permission, respectively. Use the names previously referred for the permission rights. These commands require a ROLE_MOD permission."""
        # POST /api/v1/organizations/roles/<string:role>/permissions
        # POST /api/v1/organizations/roles/<string:role>/subjects
        if permissionOrUsername in DocumentPermissions.values():
            return requests.post(f'{self.server_address}/api/v1/organizations/roles/{role}/permissions', json={'session_file': session_file, 'permission': permissionOrUsername})
        else:
            return requests.post(f'{self.server_address}/api/v1/organizations/roles/{role}/subjects', json={'session_file': session_file, 'username': permissionOrUsername})

    # ---- Next iteration ----
    def rep_remove_permission(self, session_file, role, permissionOrUsername):
        """These commands change the properties of a role in the organization with which I have currently a session, by adding a subject, removing a subject, adding a permission or removing a permission, respectively. Use the names previously referred for the permission rights. These commands require a ROLE_MOD permission."""
        # POST /api/v1/organizations/roles/<string:role>/permissions
        # POST /api/v1/organizations/roles/<string:role>/subjects
        if permissionOrUsername in DocumentPermissions.values():
            return requests.delete(f'{self.server_address}/api/v1/organizations/roles/{role}/permissions', json={'session_file': session_file, 'permission': permissionOrUsername})
        else:
            return requests.delete(f'{self.server_address}/api/v1/organizations/roles/{role}/subjects', json={'session_file': session_file, 'username': permissionOrUsername})

    def rep_add_doc(self, session_file, document_name, file):
        """This command adds a document with a given name to the organization with which I have currently a session. The document’s contents is provided as parameter with a file name. This commands requires a DOC_NEW permission."""
        # POST /api/v1/organizations/documents
        return requests.post(f'{self.server_address}/api/v1/organizations/documents', json={'session_file': session_file, 'document_name': document_name, 'file': file})

    def rep_get_doc_metadata(self, session_file, document_name):
        """This command fetches the metadata of a document with a given name to the organization with which I have currently a session. The output of this command is useful for getting the clear text contents of a document’s file. This commands requires a DOC_READ permission."""
        # GET /api/v1/organizations/documents/<string:document_name>/metadata
        return requests.get(f'{self.server_address}/api/v1/organizations/documents/{document_name}/metadata', json={'session_file': session_file})

    def rep_get_doc_file(self, session_file, document_name, file=None):
        """This command is a combination of rep_get_doc_metadata with rep_get_file and rep_decrypt_file. The file contents are written to stdout or to the file referred in the optional last argument. This commands requires a DOC_READ permission."""
        # GET /api/v1/organizations/documents/<string:document_name>/file
        return requests.get(f'{self.server_address}/api/v1/organizations/documents/{document_name}/file', json={'session_file': session_file})

    def rep_delete_doc(self, session_file, document_name):
        """This command clears file_handle in the metadata of a document with a given name on the organization with which I have currently a session. The output of this command is the file_handle that ceased to exist in the document’s metadata. This commands requires a DOC_DELETE permission."""
        # DELETE /api/v1/organizations/documents/<string:document_name>
        return requests.delete(f'{self.server_address}/api/v1/organizations/documents/{document_name}', json={'session_file': session_file})

    # ---- Next iteration ----
    def rep_acl_doc(self, session_file, document_name, operation, role, permission):
        """This command changes the ACL of a document by adding (+) or removing (-) a permission for a given role. Use the names previously referred for the permission rights. This commands requires a DOC_ACL permission."""
        # GET /api/v1/organizations/documents/<string:document_name>/acl
        return requests.get(f'{self.server_address}/api/v1/organizations/documents/{document_name}/acl', json={'session_file': session_file, 'operation': operation, 'role': role, 'permission': permission})
