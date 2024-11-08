import requests
from views.roles import DocumentPermissions

class Command:
    def __init__(self, logger, state):
        self.logger = logger
        self.state = state
        self.server_address = state['REP_ADDRESS']
        self.server_pub_key = state['REP_PUB_KEY']

class Auth(Command):
    
    def __init__(self, logger, state):
        super().__init__(logger, state)
        
    
    def rep_create_org(self, organization, username, name, email, public_key_file):
        """This command creates an organization in a Repository and defines its first subject."""
        # POST /api/v1/auth/organization
        with open(public_key_file, "r"):
            
        return requests.post(f'{self.server_address}/api/v1/auth/organization', json={'organization': organization, 'username': username, 'name': name, 'email': email, 'public_key_file': public_key_file})

    def rep_create_session(self, organization, username, password, credentials_file, session_file):
        """This command creates a session for a username belonging to an organization, and stores the session context in a file."""
        # POST /api/v1/auth/session
        return requests.post(f'{self.server_address}/api/v1/auth/session', json={'organization': organization, 'username': username, 'password': password, 'credentials_file': credentials_file, 'session_file': session_file})

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

    def rep_assume_role(self, session_file, role):
        """This command requests the given role for the session"""
        # POST /api/v1/sessions/roles
        return requests.post(f'{self.server_address}/api/v1/sessions/roles', json={'session_file': session_file, 'role': role})
    
    def rep_list_roles(self, session_file):
        """Lists the current session roles."""
        # GET /api/v1/sessions/roles
        return requests.get(f'{self.server_address}/api/v1/sessions/roles', json={'session_file': session_file})
    
    def rep_drop_role(self, session_file, role):
        """This command releases the given role for the session"""
        # DELETE /api/v1/sessions/roles
        return requests.delete(f'{self.server_address}/api/v1/sessions/roles', json={'session_file': session_file, 'role': role})
    
class Organization(Command):
    
    def __init__(self, logger, state):
        super().__init__(logger, state)
    
    def rep_list_orgs(self):
        """This command lists all organizations defined in a Repository."""
        # GET /api/v1/organizations
        return requests.get(f'{self.server_address}/api/v1/organizations')

    def rep_list_subjects(self, session_file, username=None):
        """This command lists the subjects of the organization with which I have currently a session. The listing should show the status of all the subjects (active or suspended). This command accepts an extra command to show only one subject."""
        # GET /api/v1/organizations/subjects/<string:username>/status
        # GET /api/v1/organizations/subjects/status
        if username:
            return requests.get(f'{self.server_address}/api/v1/organizations/subjects/{username}/status', json={'session_file': session_file})
        else:
            return requests.get(f'{self.server_address}/api/v1/organizations/subjects/status', json={'session_file': session_file})

    def rep_list_role_subjects(self, session_file, role):
        """This command lists the subjects of a role of the organization with which I have currently a session"""
        # GET /api/v1/organizations/roles/<string:role>/subjects
        return requests.get(f'{self.server_address}/api/v1/organizations/roles/{role}/subjects', json={'session_file': session_file})
    
    def rep_list_subject_roles(self, session_file, username):
        """This command lists the roles of a subject of the organization with which I have currently a session."""
        # GET /api/v1/organizations/subjects/<string:username>/roles
        return requests.get(f'{self.server_address}/api/v1/organizations/subjects/{username}/roles', json={'session_file': session_file})
    
    def rep_list_role_permissions(self, session_file, role):
        """This command lists the permissions of a role of the organization with which I have currently a session."""
        # GET /api/v1/organizations/roles/<string:role>/permissions
        return requests.get(f'{self.server_address}/api/v1/organizations/roles/{role}/permissions', json={'session_file': session_file})

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

    def rep_add_role(self, session_file, role):
        """This command adds a role to the organization with which I have currently a session. This commands requires a ROLE_NEW permission."""
        # POST /api/v1/organizations/roles
        return requests.post(f'{self.server_address}/api/v1/organizations/roles', json={'session_file': session_file, 'role': role})

    def rep_suspend_role(self, session_file, role):
        """These commands change the status of a role in the organization with which I have currently a session. These commands require a ROLE_DOWN and ROLE_UP permission, respectively."""
        # PUT /api/v1/organizations/roles/<string:role>/status
        return requests.put(f'{self.server_address}/api/v1/organizations/roles/{role}/status', json={'session_file': session_file})

    def rep_reactivate_role(self, session_file, role):
        """These commands change the status of a role in the organization with which I have currently a session. These commands require a ROLE_DOWN and ROLE_UP permission, respectively."""
        # PUT /api/v1/organizations/roles/<string:role>/status
        return requests.put(f'{self.server_address}/api/v1/organizations/roles/{role}/status', json={'session_file': session_file})

    def rep_add_permission(self, session_file, role, permissionOrUsername):
        """These commands change the properties of a role in the organization with which I have currently a session, by adding a subject, removing a subject, adding a permission or removing a permission, respectively. Use the names previously referred for the permission rights. These commands require a ROLE_MOD permission."""
        # POST /api/v1/organizations/roles/<string:role>/permissions
        # POST /api/v1/organizations/roles/<string:role>/subjects
        if permissionOrUsername in DocumentPermissions.values():
            return requests.post(f'{self.server_address}/api/v1/organizations/roles/{role}/permissions', json={'session_file': session_file, 'permission': permissionOrUsername})
        else:
            return requests.post(f'{self.server_address}/api/v1/organizations/roles/{role}/subjects', json={'session_file': session_file, 'username': permissionOrUsername})

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

    def rep_acl_doc(self, session_file, document_name, operation, role, permission):
        """This command changes the ACL of a document by adding (+) or removing (-) a permission for a given role. Use the names previously referred for the permission rights. This commands requires a DOC_ACL permission."""
        # GET /api/v1/organizations/documents/<string:document_name>/acl
        return requests.get(f'{self.server_address}/api/v1/organizations/documents/{document_name}/acl', json={'session_file': session_file, 'operation': operation, 'role': role, 'permission': permission})
