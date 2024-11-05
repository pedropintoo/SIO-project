import commands


API_BASE_URL = 'http://localhost:8080'

class Auth:
    
    @staticmethod
    def rep_create_org(organization, username, name, email, public_key_file):
        """Creates an organization in a Repository and defines its first subject."""
        pass

    @staticmethod
    def rep_create_session(organization, username, password, credentials_file, session_file):
        """Creates a session for a username belonging to an organization, and stores the session context in a file."""
        pass

class Organization:
    
    @staticmethod
    def rep_list_orgs():
        """Lists all organizations defined in a Repository."""
        pass

    @staticmethod
    def rep_get_file(file_handle, file=None):
        """Downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument."""
        pass

def rep_assume_role(session_file, role):
    """Requests the given role for the session."""
    pass

def rep_drop_role(session_file, role):
    """Releases the given role for the session."""
    pass

def rep_list_roles(session_file):
    """Lists the current session roles."""
    pass

def rep_list_subjects(session_file, username=None):
    """Lists the subjects of the organization with the current session. Optionally, show only one subject."""
    pass

def rep_list_role_subjects(session_file, role):
    """Lists the subjects of a role of the organization with the current session."""
    pass

def rep_list_subject_roles(session_file, username):
    """Lists the roles of a subject of the organization with the current session."""
    pass

def rep_list_role_permissions(session_file, role):
    """Lists the permissions of a role of the organization with the current session."""
    pass

def rep_list_permission_roles(session_file, permission):
    """Lists the roles that have a given permission in the organization with the current session."""
    pass

def rep_list_docs(session_file, username=None, date_filter=None, date=None):
    """Lists the documents of the organization with the current session, possibly filtered by a subject and date."""
    pass

def rep_add_subject(session_file, username, name, email, credentials_file):
    """Adds a new subject to the organization with the current session."""
    pass

def rep_suspend_subject(session_file, username):
    """Suspends a subject in the organization with the current session."""
    pass

def rep_activate_subject(session_file, username):
    """Activates a subject in the organization with the current session."""
    pass

def rep_add_role(session_file, role):
    """Adds a role to the organization with the current session."""
    pass

def rep_suspend_role(session_file, role):
    """Suspends a role in the organization with the current session."""
    pass

def rep_reactivate_role(session_file, role):
    """Reactivates a role in the organization with the current session."""
    pass

def rep_add_permission(session_file, role, permission):
    """Adds a permission to a role in the organization with the current session."""
    pass

def rep_remove_permission(session_file, role, permission):
    """Removes a permission from a role in the organization with the current session."""
    pass

def rep_add_doc(session_file, document_name, file):
    """Adds a document to the organization with the current session."""
    pass

def rep_get_doc_metadata(session_file, document_name):
    """Fetches the metadata of a document in the organization with the current session."""
    pass

def rep_get_doc_file(session_file, document_name, file=None):
    """Downloads a document file in the organization with the current session."""
    pass

def rep_delete_doc(session_file, document_name):
    """Deletes a document in the organization with the current session."""
    pass

def rep_acl_doc(session_file, document_name, operation, role, permission):
    """Changes the ACL of a document in the organization with the current session."""
    pass

if __name__ == '__main__':
    commands.RepClient().cmdloop()