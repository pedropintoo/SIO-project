from metadata_db.metadata_db import MetadataDB
from views.metadata import Metadata, AccessControlList, DocumentPermissions

metadata_db = MetadataDB('metadata_db/metadata.json')
metadata = Metadata(
    document_handle='123452',
    name='document1',
    create_date='2021-01-01',
    creator='user1',
    file_handle='123456',
    acl=AccessControlList(permissions=[DocumentPermissions.DOC_READ, DocumentPermissions.DOC_DELETE]),
    deleter=None,
    alg='EC 256',
    key='12345678910'
)
metadata_db.insert_metadata('org1', 'doc2', metadata)
print(metadata_db.get_metadata('org1', 'doc2'))
# metadata_db.delete_metadata('org1', 'doc2', 'user1')
# print(metadata_db.get_metadata('org1', 'doc2'))