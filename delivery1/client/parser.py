from argparse import ArgumentParser
from inspect import signature
from client.commands import Local, Auth, Session, Organization, File
import sys

class CommandsParser():

    def __init__(self, parser):
        self.parser = parser

        self.parser_rep_subject_credentials()
        self.parser_rep_decrypt_file()

        self.parser_rep_create_org()
        self.parser_rep_list_orgs()
        self.parser_rep_create_session()
        self.parser_rep_get_file()
        
        self.parser_rep_assume_role()
        self.parser_rep_drop_role()
        self.parser_rep_list_roles()
        self.parser_rep_list_subjects()
        self.parser_rep_list_role_subjects()
        self.parser_rep_list_subject_roles()
        self.parser_rep_list_role_permissions()
        self.parser_rep_list_permission_roles()
        self.parser_rep_list_docs()
        
        self.parser_rep_add_subject()
        self.parser_rep_suspend_subject()
        self.parser_rep_activate_subject()
        self.parser_rep_add_role()
        self.parser_rep_suspend_role()
        self.parser_rep_reactivate_role()
        self.parser_rep_add_permission()
        self.parser_rep_remove_permission()
        self.parser_rep_add_doc()
        self.parser_rep_get_doc_metadata()
        self.parser_rep_get_doc_file()
        self.parser_rep_delete_doc()
        self.parser_rep_acl_doc()

    @staticmethod
    def execute(logger, state, args):
        command = args.command
        if not command:
            logger.error("No command provided")
            sys.exit(-1)
        
        local = Local(logger, state)
        auth = Auth(logger, state)
        file = File(logger, state)
        organization = Organization(logger, state)
        session = Session(logger, state)
        
        # Command-function mapping
        command_functions = {
            'rep_subject_credentials': local.rep_subject_credentials,
            'rep_decrypt_file': local.rep_decrypt_file,
            'rep_create_org': auth.rep_create_org,
            'rep_list_orgs': organization.rep_list_orgs,
            'rep_create_session': auth.rep_create_session,
            'rep_get_file': file.rep_get_file,
            'rep_assume_role': session.rep_assume_role,
            'rep_drop_role': session.rep_drop_role,
            'rep_list_roles': session.rep_list_roles,
            'rep_list_subjects': organization.rep_list_subjects,
            'rep_list_role_subjects': organization.rep_list_role_subjects,
            'rep_list_subject_roles': organization.rep_list_subject_roles,
            'rep_list_role_permissions': organization.rep_list_role_permissions,
            'rep_list_permission_roles': organization.rep_list_permission_roles,
            'rep_list_docs': organization.rep_list_docs,
            'rep_add_subject': organization.rep_add_subject,
            'rep_suspend_subject': organization.rep_suspend_subject,
            'rep_activate_subject': organization.rep_activate_subject,
            'rep_add_role': organization.rep_add_role,
            'rep_suspend_role': organization.rep_suspend_role,
            'rep_reactivate_role': organization.rep_reactivate_role,
            'rep_add_permission': organization.rep_add_permission,
            'rep_remove_permission': organization.rep_remove_permission,
            'rep_add_doc': organization.rep_add_doc,
            'rep_get_doc_metadata': organization.rep_get_doc_metadata,
            'rep_get_doc_file': organization.rep_get_doc_file,
            'rep_delete_doc': organization.rep_delete_doc,
            'rep_acl_doc': organization.rep_acl_doc,
        }
        command_func = command_functions.get(command)
        
        # Extract arguments to pass to the command function
        func_args = vars(args)
        valid_params = signature(command_func).parameters.keys()
        filtered_args = {k: v for k, v in func_args.items() if k in valid_params}
        
        # Call the command function with arguments
        try:
            command_func(**filtered_args)
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            sys.exit(-1)
        
    ## Local commands

    def parser_rep_subject_credentials(self):
        """This command generates a new key pair and stores it in the specified file.

        Usage:
            rep_subject_credentials <password> <credentials_file>
        """
        subparser = self.parser.add_parser('rep_subject_credentials', help='This command generates a new key pair and stores it in the specified file.')
        subparser.add_argument('password', help='Password to generate the key pair')
        subparser.add_argument('credentials_file', help='Path to the credentials file')

    def parser_rep_decrypt_file(self):
        """This command sends to the stdout the contents of an encrypted file upon decryption (and integrity control) with the encryption metadata.

        Usage:
            rep_decrypt_file <encrypted file> <encryption metadata>
        """
        subparser = self.parser.add_parser('rep_decrypt_file', help='This command sends to the stdout the contents of an encrypted file upon decryption (and integrity control) with the encryption metadata.')
        subparser.add_argument('encrypted_file', help='Path to the encrypted file')
        subparser.add_argument('encryption_metadata', help='Path to the encryption metadata')

    ## Commands that use the anonymous API
    
    def parser_rep_create_org(self):
        """This command creates an organization in a Repository and defines its first subject.

        Usage:
            rep_create_org <organization> <username> <name> <email> <public_key_file>
        """
        subparser = self.parser.add_parser('rep_create_org', help='This command creates an organization in a Repository and defines its first subject.')
        subparser.add_argument('organization', help='Organization name')
        subparser.add_argument('username', help='Subject username')
        subparser.add_argument('name', help='Subject name')
        subparser.add_argument('email', help='Subject email')
        subparser.add_argument('public_key_file', help='Path to the public key file')

    def parser_rep_list_orgs(self):
        """This command lists all organizations defined in a Repository.

        Usage:
            rep_list_orgs
        """
        subparser = self.parser.add_parser('rep_list_orgs', help='This command lists all organizations defined in a Repository.')

    def parser_rep_create_session(self):
        """This command creates a session for a username belonging to an organization, and stores the session context in a file.

        Usage:
            rep_create_session <organization> <username> <password> <credentials_file> <session_file>
        """
        subparser = self.parser.add_parser('rep_create_session', help='This command creates a session for a username belonging to an organization, and stores the session context in a file.')
        subparser.add_argument('organization', help='Organization name')
        subparser.add_argument('username', help='Subject username')
        subparser.add_argument('password', help='Subject password')
        subparser.add_argument('credentials_file', help='Path to the credentials file')
        subparser.add_argument('session_file', help='Path to the session file')

    def parser_rep_get_file(self):
        """This command downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument.

        Usage:
            rep_get_file <file_handle> [file]
        """
        subparser = self.parser.add_parser('rep_get_file', help='This command downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument.')
        subparser.add_argument('file_handle', help='Handle of the file to download')
        subparser.add_argument('file', nargs='?', help='Path to the file to write the contents to')

    ## Commands that use the authenticated API

    def parser_rep_assume_role(self):
        """This command requests the given role for the session.

        Usage:
            rep_assume_role <session_file> <role>
        """
        subparser = self.parser.add_parser('rep_assume_role', help='This command requests the given role for the session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('role', help='Role to assume')

    def parser_rep_drop_role(self):
        """This command releases the given role for the session.

        Usage:
            rep_drop_role <session_file> <role>
        """
        subparser = self.parser.add_parser('rep_drop_role', help='This command releases the given role for the session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('role', help='Role to drop')

    def parser_rep_list_roles(self):
        """This command lists the current session roles.

        Usage:
            rep_list_roles <session_file>
        """
        subparser = self.parser.add_parser('rep_list_roles', help='This command lists the current session roles.')
        subparser.add_argument('session_file', help='Path to the session file')

    def parser_rep_list_subjects(self):
        """This command lists the subjects of the organization with the current session. Optionally, show only one subject.

        Usage:
            rep_list_subjects <session_file> [username]
        """
        subparser = self.parser.add_parser('rep_list_subjects', help='This command lists the subjects of the organization with the current session. Optionally, show only one subject.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('username', nargs='?', help='Username to filter')

    def parser_rep_list_role_subjects(self):
        """This command lists the subjects of a role of the organization with the current session.

        Usage:
            rep_list_role_subjects <session_file> <role>
        """
        subparser = self.parser.add_parser('rep_list_role_subjects', help='This command lists the subjects of a role of the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('role', help='Role to list subjects for')

    def parser_rep_list_subject_roles(self):
        """This command lists the roles of a subject of the organization with the current session.

        Usage:
            rep_list_subject_roles <session_file> <username>
        """
        subparser = self.parser.add_parser('rep_list_subject_roles', help='This command lists the roles of a subject of the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('username', help='Username to list roles for')

    def parser_rep_list_role_permissions(self):
        """This command lists the permissions of a role of the organization with the current session.

        Usage:
            rep_list_role_permissions <session_file> <role>
        """
        subparser = self.parser.add_parser('rep_list_role_permissions', help='This command lists the permissions of a role of the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('role', help='Role to list permissions for')

    def parser_rep_list_permission_roles(self):
        """This command lists the roles that have a given permission in the organization with the current session.

        Usage:
            rep_list_permission_roles <session_file> <permission>
        """
        subparser = self.parser.add_parser('rep_list_permission_roles', help='This command lists the roles that have a given permission in the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('permission', help='Permission to filter roles by')

    def parser_rep_list_docs(self):
        """This command lists the documents of the organization with the current session, possibly filtered by a subject and date.

        Usage:
            rep_list_docs <session_file> [-s <username>] [-d <date_filter> <date>]
        """
        subparser = self.parser.add_parser('rep_list_docs', help='This command lists the documents of the organization with the current session, possibly filtered by a subject and date.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('-s', '--subject', dest='username', help='Username to filter by')
        subparser.add_argument('-d', '--date', nargs=2, metavar=('DATE_FILTER', 'DATE'),
                            help='Date filter (nt/ot/et) and date in DD-MM-YYYY')

    ## Commands that use the authorized API

    def parser_rep_add_subject(self):
        """This command adds a new subject to the organization with the current session.

        Usage:
            rep_add_subject <session_file> <username> <name> <email> <credentials_file>
        """
        subparser = self.parser.add_parser('rep_add_subject', help='This command adds a new subject to the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('username', help='Username of the new subject')
        subparser.add_argument('name', help='Name of the new subject')
        subparser.add_argument('email', help='Email of the new subject')
        subparser.add_argument('credentials_file', help='Path to the credentials file')

    def parser_rep_suspend_subject(self):
        """This command suspends a subject in the organization with the current session.

        Usage:
            rep_suspend_subject <session_file> <username>
        """
        subparser = self.parser.add_parser('rep_suspend_subject', help='This command suspends a subject in the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('username', help='Username of the subject to suspend')

    def parser_rep_activate_subject(self):
        """This command activates a subject in the organization with the current session.

        Usage:
            rep_activate_subject <session_file> <username>
        """
        subparser = self.parser.add_parser('rep_activate_subject', help='This command activates a subject in the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('username', help='Username of the subject to activate')

    def parser_rep_add_role(self):
        """This command adds a role to the organization with the current session.

        Usage:
            rep_add_role <session_file> <role>
        """
        subparser = self.parser.add_parser('rep_add_role', help='This command adds a role to the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('role', help='Role to add')

    def parser_rep_suspend_role(self):
        """This command suspends a role in the organization with the current session.

        Usage:
            rep_suspend_role <session_file> <role>
        """
        subparser = self.parser.add_parser('rep_suspend_role', help='This command suspends a role in the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('role', help='Role to suspend')

    def parser_rep_reactivate_role(self):
        """This command reactivates a role in the organization with the current session.

        Usage:
            rep_reactivate_role <session_file> <role>
        """
        subparser = self.parser.add_parser('rep_reactivate_role', help='This command reactivates a role in the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('role', help='Role to reactivate')

    def parser_rep_add_permission(self):
        """This command adds a permission to a role in the organization with the current session.

        Usage:
            rep_add_permission <session_file> <role> <permissionOrUsername>
        """
        subparser = self.parser.add_parser('rep_add_permission', help='This command adds a permission or username to a role in the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('role', help='Role to add permission to')
        subparser.add_argument('permissionOrUsername', help='Permission or username to add to the role')

    def parser_rep_remove_permission(self):
        """This command removes a permission or username from a role in the organization with the current session.

        Usage:
            rep_remove_permission <session_file> <role> <permissionOrUsername>
        """
        subparser = self.parser.add_parser('rep_remove_permission', help='This command removes a permission or username from a role in the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('role', help='Role to remove permission from')
        subparser.add_argument('permissionOrUsername', help='Permission or username to remove from the role')

    def parser_rep_add_doc(self):
        """This command adds a document to the organization with the current session.

        Usage:
            rep_add_doc <session_file> <document_name> <file>
        """
        subparser = self.parser.add_parser('rep_add_doc', help='This command adds a document to the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('document_name', help='Name of the document to add')
        subparser.add_argument('file', help='Path to the file containing the document contents')

    def parser_rep_get_doc_metadata(self):
        """This command fetches the metadata of a document in the organization with the current session.

        Usage:
            rep_get_doc_metadata <session_file> <document_name>
        """
        subparser = self.parser.add_parser('rep_get_doc_metadata', help='This command fetches the metadata of a document in the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('document_name', help='Name of the document to fetch metadata for')

    def parser_rep_get_doc_file(self):
        """This command downloads a document file in the organization with the current session.

        Usage:
            rep_get_doc_file <session_file> <document_name> [file]
        """
        subparser = self.parser.add_parser('rep_get_doc_file', help='This command downloads a document file in the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('document_name', help='Name of the document to download')
        subparser.add_argument('file', nargs='?', help='Path to the file to write the contents to')

    def parser_rep_delete_doc(self):
        """This command deletes a document in the organization with the current session.

        Usage:
            rep_delete_doc <session_file> <document_name>
        """
        subparser = self.parser.add_parser('rep_delete_doc', help='This command deletes a document in the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('document_name', help='Name of the document to delete')

    def parser_rep_acl_doc(self):
        """This command changes the ACL of a document in the organization with the current session.

        Usage:
            rep_acl_doc <session_file> <document_name> [+/-] <role> <permission>
        """
        subparser = self.parser.add_parser('rep_acl_doc', help='This command changes the ACL of a document in the organization with the current session.')
        subparser.add_argument('session_file', help='Path to the session file')
        subparser.add_argument('document_name', help='Name of the document')
        subparser.add_argument('operation', choices=['+', '-'], help='Operation to perform (+ to add, - to remove)')
        subparser.add_argument('role', help='Role to change ACL for')
        subparser.add_argument('permission', help='Permission to add or remove')
    