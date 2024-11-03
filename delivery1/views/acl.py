from typing import List, NamedTuple
from views.roles import DocumentPermissions

class AccessControlList(NamedTuple):
    permissions: List[DocumentPermissions]
    
    