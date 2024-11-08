# api path: /api/v1/organizations/ 
from . import organization_bp
from flask import request
from server.organization_db.organization_db import OrganizationDB

organization_db = OrganizationDB("server/organization_db/organizations.json")

@organization_bp.route('/', methods=['GET'])
def list_orgs():
    # TODO: Logic to list organizations
    return organization_db.get_all_organizations()
    
# Roles Endpoints
@organization_bp.route('/roles/<string:role>/subjects', methods=['GET'])
def list_subjects(role):
    # TODO: Logic to get subjects in one of my organization's roles
    ...

@organization_bp.route('/roles/<string:role>/permissions', methods=['GET'])
def list_permissions(role):
    # TODO: Logic to get permissions in one of my organization's roles
    ...


@organization_bp.route('/roles', methods=['POST'])
def add_role():
    # TODO: Logic to add a role
    ...

@organization_bp.route('/roles/<string:role>/subjects', methods=['POST'])
def action_subject_to_role(role):
    # TODO: Logic to add or remove a subject from a role
    data = request.get_json()
    action = data.get('action')
    if action == 'add':
        ...
    elif action == 'remove':
        ...
    
@organization_bp.route('/roles/<string:role>/permissions', methods=['POST'])
def action_permission_to_role(role):
    # TODO: Logic to add or remove a permission from a role
    data = request.get_json()
    action = data.get('action')
    if action == 'add':
        ...
    elif action == 'remove':
        ...

@organization_bp.route('/roles/<string:role>/status', methods=['PUT'])
def update_role_status(role):
    # TODO: Logic to change role status
    data = request.get_json()
    new_status = data.get('status')
    if new_status == 'activate':
        ...
    elif new_status == 'suspend':
        ...


# Subjects Endpoints
@organization_bp.route("/subjects", methods=['POST'])
def add_subject():
    # TODO: Logic to add a subject
    ...

@organization_bp.route('/subjects/<string:username>/roles', methods=['GET'])
def list_roles_subject(username):
    # TODO: Logic to get roles of one of my organization's subjects
    ...

@organization_bp.route('/subjects/<string:username>/status', methods=['PUT'])
def update_subject_status(username):
    # TODO: Logic to change a subject status
    data = request.get_json()
    new_status = data.get('status')
    if new_status == 'activate':
        ...
    elif new_status == 'suspend':
        ...

@organization_bp.route('/subjects/<string:username>/status', methods=['GET'])
def list_subject_status(username):
    # TODO: Logic to show the status of a subject
    ...

@organization_bp.route('/subjects/status', methods=['GET'])
def list_all_subjects_status():
    # TODO: Logic to show the status of all subjects
    ...

# Permissions Endpoints
@organization_bp.route('/permissions/<string:permission>/roles', methods=['GET'])
def list_roles_permission(permission):
    # TODO: Logic to get roles that have a given permission
    ...

# Documents Endpoints
@organization_bp.route("/documents", methods=['GET'])
def list_documents():
    creator = request.args.get('creator')
    date_str = request.args.get('date')    
    date_filter = request.args.get('date_filter')
    # TODO: Logic to list documents

@organization_bp.route("/documents", methods=['POST'])
def create_document():
    # TODO: Logic to create a document
    ...

@organization_bp.route("/documents/<string:document_name>/metadata", methods=['GET'])
def get_document_metadata(document_name):
    # TODO: Logic to download metadata of a document
    ...

@organization_bp.route("/documents/<string:document_name>/file", methods=['GET'])
def get_document_file(document_name):
    # TODO: Logic to download a document file
    ...

@organization_bp.route("/documents/<string:document_name>", methods=['DELETE'])
def delete_document(document_name):
    # TODO: Logic to delete a document
    ...

@organization_bp.route("/documents/<string:document_name>/acl", methods=['PUT'])
def update_document_acl(document_name):
    # TODO: Logic to update document ACL
    data = request.get_json()
    new_acl = data.get('acl')
    ...
