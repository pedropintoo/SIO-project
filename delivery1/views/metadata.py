import json
from typing import List, NamedTuple
from views.acl import AccessControlList
from views.roles import DocumentPermissions

class Metadata(NamedTuple):
    # public attributes
    document_handle: str
    name: str
    create_date: str
    creator: str
    file_handle: str
    acl: AccessControlList
    deleter: str
    # private attributes
    alg: str
    key: str

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, DocumentPermissions):
            return o.name
        return super().default(o)
