from enum import Enum

class DocumentPermissions(Enum):
    DOC_ACL = "doc_acl"
    DOC_READ = "doc_read"
    DOC_DELETE = "doc_delete"
    
class RoleManagement(Enum):
    ROLE_NEW = "role_new"
    ROLE_DOWN = "role_down"
    ROLE_UP = "role_up"
    ROLE_MOD = "role_mod"

class OrganizationManagement(Enum):
    ROLE_ACL = "role_acl"
    SUBJECT_NEW = "subject_new"
    SUBJECT_DOWN = "subject_down"
    SUBJECT_UP = "subject_up"
    DOC_NEW = "doc_new"