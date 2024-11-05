import commands

class Auth:
    
    def rep_create_org(self, organization, username, name, email, public_key_file):
        """This command creates an organization in a Repository and defines its first subject."""
        # POST /api/v1/auth/organization
        pass

    def rep_create_session(self, organization, username, password, credentials_file, session_file):
        """This command creates a session for a username belonging to an organization, and stores the session context in a file."""
        # POST /api/v1/auth/session
        pass

class File:
        
    def rep_get_file(self, file_handle, file=None):
        """This command downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument."""
        # GET /api/v1/files/<string:file_handle>
        pass    

class Session:

    def rep_assume_role(self, session_file, role):
        """Requests the given role for the session."""
        # POST /api/v1/sessions/roles
        pass
    
    def rep_list_roles(self, session_file):
        """Lists the current session roles."""
        # GET /api/v1/sessions/roles
        pass
    
    def rep_drop_role(self, session_file, role):
        """Releases the given role for the session."""
        # DELETE /api/v1/sessions/roles
        pass
    
class Organization:
    
    def rep_list_orgs(self):
        """This command lists all organizations defined in a Repository."""
        # GET /api/v1/organizations
        pass 

    def rep_list_subjects(self, session_file, username=None):
        """This command lists the subjects of the organization with which I have currently a session. The listing should show the status of all the subjects (active or suspended). This command accepts an extra command to show only one subject."""
        # GET /api/v1/organizations/subjects/<string:username>/status
        # GET /api/v1/organizations/subjects/status
        pass

    def rep_list_role_subjects(self, session_file, role):
        """This command lists the subjects of a role of the organization with which I have currently a session"""
        # GET /api/v1/organizations/roles/<string:role>/subjects
        pass
    
    def rep_list_subject_roles(self, session_file, username):
        """This command lists the roles of a subject of the organization with which I have currently a session."""
        # GET /api/v1/organizations/subjects/<string:username>/roles
        pass
    
    def rep_list_role_permissions(self, session_file, role):
        """This command lists the permissions of a role of the organization with which I have currently a session."""
        # GET /api/v1/organizations/roles/<string:role>/permissions
        pass

    def rep_list_permission_roles(self, session_file, permission):
        # TODO: check typo in the command!!!
        """This command lists the roles of the organization with which I have currently a session that have a given permission. Use the names previously referred for the permission rights."""
        # GET /api/v1/organizations/permissions/<string:permission>/roles
        pass

    def rep_list_docs(self, session_file, username=None, date_filter=None, date=None):
        """This command lists the documents of the organization with which I have currently a session, possibly filtered by a subject that created them and by a date (newer than, older than, equal to), expressed in the DD-MM-YYYY format."""
        # GET /api/v1/organizations/documents
        pass

    def rep_add_subject(self, session_file, username, name, email, credentials_file):
        """Adds a new subject to the organization with the current session."""
        # POST /api/v1/organizations/subjects
        pass

    def rep_suspend_subject(self, session_file, username):
        """Suspends a subject in the organization with the current session."""
        # PUT /api/v1/organizations/subjects/<string:username>/status
        pass

    def rep_activate_subject(self, session_file, username):
        """Activates a subject in the organization with the current session."""
        # PUT /api/v1/organizations/subjects/<string:username>/status
        pass

    def rep_add_role(self, session_file, role):
        """Adds a role to the organization with the current session."""
        # POST /api/v1/organizations/roles
        pass

    def rep_suspend_role(self, session_file, role):
        """Suspends a role in the organization with the current session."""
        # PUT /api/v1/organizations/roles/<string:role>/status
        pass

    def rep_reactivate_role(self, session_file, role):
        """Reactivates a role in the organization with the current session."""
        # PUT /api/v1/organizations/roles/<string:role>/status
        pass

    def rep_add_permission(self, session_file, role, permissionOrUser):
        """Adds a permission or a username to a role in the organization with the current session."""
        # POST /api/v1/organizations/roles/<string:role>/permissions
        # POST /api/v1/organizations/roles/<string:role>/subjects
        pass

    def rep_remove_permission(self, session_file, role, permission):
        """Removes a permission or a username from a role in the organization with the current session."""
        # POST /api/v1/organizations/roles/<string:role>/permissions
        # POST /api/v1/organizations/roles/<string:role>/subjects
        pass

    def rep_add_doc(session_file, document_name, file):
        """Adds a document to the organization with the current session."""
        # POST /api/v1/organizations/documents
        pass

    def rep_get_doc_metadata(session_file, document_name):
        """Fetches the metadata of a document in the organization with the current session."""
        # GET /api/v1/organizations/documents/<string:document_name>/metadata
        pass

    def rep_get_doc_file(session_file, document_name, file=None):
        """Downloads a document file in the organization with the current session."""
        # GET /api/v1/organizations/documents/<string:document_name>/file
        pass

    def rep_delete_doc(session_file, document_name):
        """Deletes a document in the organization with the current session."""
        # DELETE /api/v1/organizations/documents/<string:document_name>
        pass

    def rep_acl_doc(session_file, document_name, operation, role, permission):
        """Changes the ACL of a document in the organization with the current session."""
        # GET /api/v1/organizations/documents/<string:document_name>/acl
        pass

if __name__ == '__main__':
    commands.RepClient().cmdloop()