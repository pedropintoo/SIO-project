from typing import List, NamedTuple
from roles import DocumentPermissions

class AccessControlList(NamedTuple):
    permissions: List[DocumentPermissions]
    
    