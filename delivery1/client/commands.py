import cmd
import shlex
from argparse import ArgumentParser
from run import Auth, Organization, Session, File

auth = Auth()
organization = Organization()
session = Session()
file = File()

class RepClient(cmd.Cmd):
    prompt = '\33[1;32mrep> \33[0m'
    intro = '\33[1;33mWelcome to the Repository client. Type `help` or `?` to list commands.\33[0m\n'

    ## Commands that use the anonymous API
    
    def do_rep_create_org(self, arg):
        """This command creates an organization in a Repository and defines its first subject.

        Usage:
            rep_create_org <organization> <username> <name> <email> <public_key_file>
        """
        parser = ArgumentParser(prog='rep_create_org')
        parser.add_argument('organization', help='Organization name')
        parser.add_argument('username', help='Subject username')
        parser.add_argument('name', help='Subject name')
        parser.add_argument('email', help='Subject email')
        parser.add_argument('public_key_file', help='Path to the public key file')
        try:
            args = parser.parse_args(shlex.split(arg))
            auth.rep_create_org(args.organization, args.username, args.name, args.email, args.public_key_file)
        except SystemExit:
            print(self.do_rep_create_org.__doc__)

    def do_rep_list_orgs(self, arg):
        """This command lists all organizations defined in a Repository.

        Usage:
            rep_list_orgs
        """
        organization.rep_list_orgs()

    def do_rep_create_session(self, arg):
        """This command creates a session for a username belonging to an organization, and stores the session context in a file.

        Usage:
            rep_create_session <organization> <username> <password> <credentials_file> <session_file>
        """
        parser = ArgumentParser(prog='rep_create_session')
        parser.add_argument('organization', help='Organization name')
        parser.add_argument('username', help='Subject username')
        parser.add_argument('password', help='Subject password')
        parser.add_argument('credentials_file', help='Path to the credentials file')
        parser.add_argument('session_file', help='Path to the session file')
        try:
            args = parser.parse_args(shlex.split(arg))
            auth.rep_create_session(args.organization, args.username, args.password, args.credentials_file, args.session_file)
        except SystemExit:
            print(self.do_rep_create_session.__doc__)

    def do_rep_get_file(self, arg):
        """This command downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument.

        Usage:
            rep_get_file <file_handle> [file]
        """
        parser = ArgumentParser(prog='rep_get_file')
        parser.add_argument('file_handle', help='Handle of the file to download')
        parser.add_argument('file', nargs='?', help='Path to the file to write the contents to')
        try:
            args = parser.parse_args(shlex.split(arg))
            file.rep_get_file(args.file_handle, args.file)
        except SystemExit:
            print(self.do_rep_get_file.__doc__)

    ## Commands that use the authenticated API

    def do_rep_assume_role(self, arg):
        """This command requests the given role for the session

        Usage:
            rep_assume_role <session_file> <role>
        """
        parser = ArgumentParser(prog='rep_assume_role')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('role', help='Role to assume')
        try:
            args = parser.parse_args(shlex.split(arg))
            session.rep_assume_role(args.session_file, args.role)
        except SystemExit:
            print(self.do_rep_assume_role.__doc__)

    def do_rep_drop_role(self, arg):
        """This command releases the given role for the session

        Usage:
            rep_drop_role <session_file> <role>
        """
        parser = ArgumentParser(prog='rep_drop_role')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('role', help='Role to drop')
        try:
            args = parser.parse_args(shlex.split(arg))
            session.rep_drop_role(args.session_file, args.role)
        except SystemExit:
            print(self.do_rep_drop_role.__doc__)

    def do_rep_list_roles(self, arg):
        """This command lists the current session roles

        Usage:
            rep_list_roles <session_file>
        """
        parser = ArgumentParser(prog='rep_list_roles')
        parser.add_argument('session_file', help='Path to the session file')
        try:
            args = parser.parse_args(shlex.split(arg))
            session.rep_list_roles(args.session_file)
        except SystemExit:
            print(self.do_rep_list_roles.__doc__)

    def do_rep_list_subjects(self, arg):
        """This command lists the subjects of the organization with which I have currently a session. The listing should show the status of all the subjects (active or suspended). This command accepts an extra command to show only one subject.

        Usage:
            rep_list_subjects <session_file> [username]
        """
        parser = ArgumentParser(prog='rep_list_subjects')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('username', nargs='?', help='Username to filter')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_list_subjects(args.session_file, args.username)
        except SystemExit:
            print(self.do_rep_list_subjects.__doc__)

    def do_rep_list_role_subjects(self, arg):
        """This command lists the subjects of a role of the organization with which I have currently a session.

        Usage:
            rep_list_role_subjects <session_file> <role>
        """
        parser = ArgumentParser(prog='rep_list_role_subjects')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('role', help='Role to list subjects for')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_list_role_subjects(args.session_file, args.role)
        except SystemExit:
            print(self.do_rep_list_role_subjects.__doc__)

    def do_rep_list_subject_roles(self, arg):
        """This command lists the roles of a subject of the organization with which I have currently a session.

        Usage:
            rep_list_subject_roles <session_file> <username>
        """
        parser = ArgumentParser(prog='rep_list_subject_roles')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('username', help='Username to list roles for')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_list_subject_roles(args.session_file, args.username)
        except SystemExit:
            print(self.do_rep_list_subject_roles.__doc__)

    def do_rep_list_role_permissions(self, arg):
        """This command lists the permissions of a role of the organization with which I have currently a session.

        Usage:
            rep_list_role_permissions <session_file> <role>
        """
        parser = ArgumentParser(prog='rep_list_role_permissions')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('role', help='Role to list permissions for')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_list_role_permissions(args.session_file, args.role)
        except SystemExit:
            print(self.do_rep_list_role_permissions.__doc__)

    def do_rep_list_permission_roles(self, arg):
        """This command lists the roles of the organization with which I have currently a session that have a given permission. Use the names previously referred for the permission rights.

        Usage:
            rep_list_permission_roles <session_file> <permission>
        """
        parser = ArgumentParser(prog='rep_list_permission_roles')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('permission', help='Permission to filter roles by')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_list_permission_roles(args.session_file, args.permission)
        except SystemExit:
            print(self.do_rep_list_permission_roles.__doc__)

    def do_rep_list_docs(self, arg):
        """This command lists the documents of the organization with which I have currently a session, possibly filtered by a subject that created them and by a date (newer than, older than, equal to), expressed in the DD-MM-YYYY format.

        Usage:
            rep_list_docs <session_file> [-s <username>] [-d <date_filter> <date>]
        """
        parser = ArgumentParser(prog='rep_list_docs')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('-s', '--subject', dest='username', help='Username to filter by')
        parser.add_argument('-d', '--date', nargs=2, metavar=('DATE_FILTER', 'DATE'),
                            help='Date filter (nt/ot/et) and date in DD-MM-YYYY')
        try:
            args = parser.parse_args(shlex.split(arg))
            session_file = args.session_file
            username = args.username
            if args.date:
                date_filter, date = args.date
            else:
                date_filter = date = None
            organization.rep_list_docs(session_file, username, date_filter, date)
        except SystemExit:
            print(self.do_rep_list_docs.__doc__)

    ## Commands that use the authorized API

    def do_rep_add_subject(self, arg):
        """This command adds a new subject to the organization with which I have currently a session. By default the subject is created in the active status. This commands requires a SUBJECT_NEW permission.

        Usage:
            rep_add_subject <session_file> <username> <name> <email> <credentials_file>
        """
        parser = ArgumentParser(prog='rep_add_subject')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('username', help='Username of the new subject')
        parser.add_argument('name', help='Name of the new subject')
        parser.add_argument('email', help='Email of the new subject')
        parser.add_argument('credentials_file', help='Path to the credentials file')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_add_subject(args.session_file, args.username, args.name, args.email, args.credentials_file)
        except SystemExit:
            print(self.do_rep_add_subject.__doc__)

    def do_rep_suspend_subject(self, arg):
        """These commands change the status of a subject in the organization with which I have currently a session. These commands require a SUBJECT_DOWN and SUBJECT_UP permission, respectively.

        Usage:
            rep_suspend_subject <session_file> <username>
        """
        parser = ArgumentParser(prog='rep_suspend_subject')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('username', help='Username of the subject to suspend')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_suspend_subject(args.session_file, args.username)
        except SystemExit:
            print(self.do_rep_suspend_subject.__doc__)

    def do_rep_activate_subject(self, arg):
        """These commands change the status of a subject in the organization with which I have currently a session. These commands require a SUBJECT_DOWN and SUBJECT_UP permission, respectively.
        
        Usage:
            rep_activate_subject <session_file> <username>
        """
        parser = ArgumentParser(prog='rep_activate_subject')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('username', help='Username of the subject to activate')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_activate_subject(args.session_file, args.username)
        except SystemExit:
            print(self.do_rep_activate_subject.__doc__)

    def do_rep_add_role(self, arg):
        """This command adds a role to the organization with which I have currently a session. This commands requires a ROLE_NEW permission.

        Usage:
            rep_add_role <session_file> <role>
        """
        parser = ArgumentParser(prog='rep_add_role')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('role', help='Role to add')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_add_role(args.session_file, args.role)
        except SystemExit:
            print(self.do_rep_add_role.__doc__)

    def do_rep_suspend_role(self, arg):
        """These commands change the status of a role in the organization with which I have currently a session. These commands require a ROLE_DOWN and ROLE_UP permission, respectively.

        Usage:
            rep_suspend_role <session_file> <role>
        """
        parser = ArgumentParser(prog='rep_suspend_role')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('role', help='Role to suspend')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_suspend_role(args.session_file, args.role)
        except SystemExit:
            print(self.do_rep_suspend_role.__doc__)

    def do_rep_reactivate_role(self, arg):
        """These commands change the status of a role in the organization with which I have currently a session. These commands require a ROLE_DOWN and ROLE_UP permission, respectively.

        Usage:
            rep_reactivate_role <session_file> <role>
        """
        parser = ArgumentParser(prog='rep_reactivate_role')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('role', help='Role to reactivate')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_reactivate_role(args.session_file, args.role)
        except SystemExit:
            print(self.do_rep_reactivate_role.__doc__)

    def do_rep_add_permission(self, arg):
        """These commands change the properties of a role in the organization with which I have currently a session, by adding a subject, removing a subject, adding a permission or removing a permission, respectively. Use the names previously referred for the permission rights. These commands require a ROLE_MOD permission.

        Usage:
            rep_add_permission <session_file> <role> <permissionOrUsername>
        """
        parser = ArgumentParser(prog='rep_add_permission')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('role', help='Role to add permission to')
        parser.add_argument('permissionOrUsername', help='Permission or username to add')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_add_permission(args.session_file, args.role, args.permissionOrUsername)
        except SystemExit:
            print(self.do_rep_add_permission.__doc__)

    def do_rep_remove_permission(self, arg):
        """These commands change the properties of a role in the organization with which I have currently a session, by adding a subject, removing a subject, adding a permission or removing a permission, respectively. Use the names previously referred for the permission rights. These commands require a ROLE_MOD permission.

        Usage:
            rep_remove_permission <session_file> <role> <permissionOrUsername>
        """
        parser = ArgumentParser(prog='rep_remove_permission')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('role', help='Role to remove permission from')
        parser.add_argument('permissionOrUsername', help='Permission or username to remove')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_remove_permission(args.session_file, args.role, args.permissionOrUsername)
        except SystemExit:
            print(self.do_rep_remove_permission.__doc__)

    def do_rep_add_doc(self, arg):
        """This command adds a document with a given name to the organization with which I have currently a session. The document’s contents is provided as parameter with a file name. This commands requires a DOC_NEW permission.

        Usage:
            rep_add_doc <session_file> <document_name> <file>
        """
        parser = ArgumentParser(prog='rep_add_doc')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('document_name', help='Name of the document to add')
        parser.add_argument('file', help='Path to the file containing the document contents')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_add_doc(args.session_file, args.document_name, args.file)
        except SystemExit:
            print(self.do_rep_add_doc.__doc__)

    def do_rep_get_doc_metadata(self, arg):
        """This command fetches the metadata of a document with a given name to the organization with which I have currently a session. The output of this command is useful for getting the clear text contents of a document’s file. This commands requires a DOC_READ permission.

        Usage:
            rep_get_doc_metadata <session_file> <document_name>
        """
        parser = ArgumentParser(prog='rep_get_doc_metadata')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('document_name', help='Name of the document to fetch metadata for')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_get_doc_metadata(args.session_file, args.document_name)
        except SystemExit:
            print(self.do_rep_get_doc_metadata.__doc__)

    def do_rep_get_doc_file(self, arg):
        """This command is a combination of rep_get_doc_metadata with rep_get_file and rep_decrypt_file. The file contents are written to stdout or to the file referred in the optional last argument. This commands requires a DOC_READ permission.

        Usage:
            rep_get_doc_file <session_file> <document_name> [file]
        """
        parser = ArgumentParser(prog='rep_get_doc_file')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('document_name', help='Name of the document to download')
        parser.add_argument('file', nargs='?', help='Path to the file to write the contents to')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_get_doc_file(args.session_file, args.document_name, args.file)
        except SystemExit:
            print(self.do_rep_get_doc_file.__doc__)

    def do_rep_delete_doc(self, arg):
        """This command clears file_handle in the metadata of a document with a given name on the organization with which I have currently a session. The output of this command is the file_handle that ceased to exist in the document’s metadata. This commands requires a DOC_DELETE permission.

        Usage:
            rep_delete_doc <session_file> <document_name>
        """
        parser = ArgumentParser(prog='rep_delete_doc')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('document_name', help='Name of the document to delete')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_delete_doc(args.session_file, args.document_name)
        except SystemExit:
            print(self.do_rep_delete_doc.__doc__)

    def do_rep_acl_doc(self, arg):
        """This command changes the ACL of a document by adding (+) or removing (-) a permission for a given role. Use the names previously referred for the permission rights. This commands requires a DOC_ACL permission.

        Usage:
            rep_acl_doc <session_file> <document_name> [+/-] <role> <permission>
        """
        parser = ArgumentParser(prog='rep_acl_doc')
        parser.add_argument('session_file', help='Path to the session file')
        parser.add_argument('document_name', help='Name of the document to change ACL for')
        parser.add_argument('operation', choices=['+', '-'], help='Operation to perform (+ to add, - to remove)')
        parser.add_argument('role', help='Role to change ACL for')
        parser.add_argument('permission', help='Permission to add or remove')
        try:
            args = parser.parse_args(shlex.split(arg))
            organization.rep_acl_doc(args.session_file, args.document_name, args.operation, args.role, args.permission)
        except SystemExit:
            print(self.do_rep_acl_doc.__doc__)
    
    ## Utility commands
    def do_exit(self, arg):
        """Exits the program.

        Usage:
            exit
        """
        print('Exiting...')
        return True
    
    def emptyline(self):
        pass
