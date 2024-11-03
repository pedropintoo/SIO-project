import json
from typing import List, NamedTuple
from acl import AccessControlList
from roles import DocumentPermissions

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

# Example usage
if __name__ == '__main__':
    metadata = Metadata(
        document_handle='123456',
        name='document1',
        create_date='2021-01-01',
        creator='user1',
        file_handle='123456',
        acl=AccessControlList(permissions=[DocumentPermissions.DOC_READ, DocumentPermissions.DOC_DELETE]),
        deleter='user2',
        alg='EC 256',
        key='12345678910'
    )
    print(json.dumps(metadata._asdict(), indent=4, cls=CustomJSONEncoder))