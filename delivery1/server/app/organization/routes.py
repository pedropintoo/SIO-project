# api path: /api/v1/organizations/ 
from . import organization_bp
from flask import jsonify, request, current_app
from organizations_db.organizations_db import OrganizationsDB
from utils import symmetric
from cryptography.exceptions import InvalidTag
import json
import base64

@organization_bp.route('/', methods=['GET'])
def list_orgs():
    return jsonify(current_app.organization_db.get_all_organizations()), 200
    
# Roles Endpoints
@organization_bp.route('/roles/<string:role>/subjects', methods=['GET'])
def list_subjects(role):
    # TODO: Logic to get subjects in one of my organization's roles
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    role_data = current_app.organization_db.retrieve_role(organization_name, role)
    
    if not role_data:
        return jsonify({'error': f'Role "{role}" not found in organization "{organization_name}"'}), 404
    
    subjects = role_data.get('subjects', [])

    if not subjects:
        return jsonify({'message': f'No subjects assigned to role "{role}" in organization "{organization_name}"'}), 200

    return jsonify(subjects), 200

@organization_bp.route('/roles/<string:role>/permissions', methods=['GET'])
def list_permissions(role):
    # TODO: Logic to get permissions in one of my organization's roles 
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    role_data = current_app.organization_db.retrieve_role(organization_name, role)

    if not role_data:
        return jsonify({'error': f'Role "{role}" not found in organization "{organization_name}"'}), 404
    
    permissions = role_data.get('permissions', [])

    if not permissions:
        return jsonify({'message': f'No permissions assigned to role "{role}" in organization "{organization_name}"'}), 200
    
    return jsonify(permissions), 200


@organization_bp.route('/roles', methods=['POST'])
def add_role(role, subjects, permissions, state):
    # TODO: Logic to add a role
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    role_details = {
        'subjects': subjects,
        'permissions': permissions,
        'state': state
    }

    current_app.organization_db.add_role(organization_name, role, role_details)

    return jsonify({f'Role "{role}" added to organization "{organization_name}"'}), 200

@organization_bp.route('/roles/<string:role>/subjects', methods=['POST'])
def action_subject_to_role(role):
    # TODO: Logic to add or remove a subject from a role
    session = request.args.get('session')   

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)  

    role_data = current_app.organization_db.retrieve_role(organization_name, role) 
    if not role_data:
        return jsonify({'error': f'Role "{role}" not found in organization "{organization_name}"'}), 404  
          
    data = request.get_json()
    action = data.get('action') 
    
    if action == 'add':
        role_data['subjects'].append(data.get('subject'))

    elif action == 'remove':
        role_data['subjects'].remove(data.get('subject'))
    
    current_app.organization_db.update_role(organization_name, role, role_data)

    return jsonify({f'Subject "{data.get("subject")}" {action}ed to role "{role}" in organization "{organization_name}"'}), 200


@organization_bp.route('/roles/<string:role>/permissions', methods=['POST'])
def action_permission_to_role(role):
    # TODO: Logic to add or remove a permission from a role
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    role_data = current_app.organization_db.retrieve_role(organization_name, role)

    if not role_data:
        return jsonify({'error': f'Role "{role}" not found in organization "{organization_name}"'}), 404

    data = request.get_json()
    action = data.get('action')    

    if action == 'add':
        role_data['permissions'].append(data.get('permission'))
    elif action == 'remove':
        role_data['permissions'].remove(data.get('permission'))

    current_app.organization_db.update_role(organization_name, role, role_data)

    return jsonify({f'Permission "{data.get("permission")}" {action}ed to role "{role}" in organization "{organization_name}"'}), 200


@organization_bp.route('/roles/<string:role>/state', methods=['PUT'])
def update_role_state(role):
    # TODO: Logic to change role state
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    role_data = current_app.organization_db.retrieve_role(organization_name, role)

    if not role_data:
        return jsonify({'error': f'Role "{role}" not found in organization "{organization_name}"'}), 404

    data = request.get_json()
    new_state = data.get('state')
    
    if new_state == 'active':
        role_data['state'] = 'active'
    elif new_state == 'suspend':
        role_data['state'] = 'suspend'

    current_app.organization_db.update_role(organization_name, role, role_data)

    return jsonify({f'Role "{role}" state updated to "{role_data["state"]}" in organization "{organization_name}"'}), 200
    
# Subjects Endpoints
@organization_bp.route("/subjects", methods=['POST'])
def add_subject(username, name, email, public_key, state):
    # TODO: Logic to add a subject
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    subject_details = {
        'name': name,
        'email': email,
        'public_key': public_key,
        'state': state
    }

    current_app.organization_db.add_subject(organization_name, username, subject_details)

@organization_bp.route('/subjects/<string:username>/roles', methods=['GET'])
def list_roles_subject(username):
    # TODO: Logic to get roles of one of my organization's subjects
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    roles = current_app.organization_db.retrieve_roles(organization_name)

    subject_roles = []
    for role, role_data in roles.items():
        if username in role_data.get('subjects', []):
            subject_roles.append(role)

    return jsonify(subject_roles), 200        

@organization_bp.route('/subjects/<string:username>/state', methods=['PUT'])
def update_subject_state(username):
    # TODO: Logic to change a subject state
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    subject_data = current_app.organization_db.retrieve_subject(organization_name, username)

    if not subject_data:
        return jsonify({'error': f'Subject "{username}" not found in organization "{organization_name}"'}), 404

    data = request.get_json()
    new_state = data.get('state')
    
    if new_state == 'active':
        subject_data["state"] = 'active'
    elif new_state == 'suspend':
        subject_data["state"] = 'suspend'
    
    current_app.organization_db.update_subject(organization_name, username, subject_data)

@organization_bp.route('/subjects/<string:username>/state', methods=['GET'])
def list_subject_state(username):
    # TODO: Logic to show the state of a subject
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    subject_data = current_app.organization_db.retrieve_subject(organization_name, username)

    if not subject_data:
        return jsonify({'error': f'Subject "{username}" not found in organization "{organization_name}"'}), 404

    return jsonify({'state': subject_data.get('state')}), 200


@organization_bp.route('/subjects/state', methods=['GET'])
def list_all_subjects_state():
    # TODO: Logic to show the state of all subjects
    data = request.get_json()
    associated_data = data.get('associated_data')
    encrypted_data = data.get('encrypted_data')

    if not associated_data or not encrypted_data:
        return jsonify({'error': f'Missing required fields: {associated_data} {encrypted_data}'}), 400

    # Associated data
    session_id = associated_data.get('session_id')
    msg_id = associated_data.get('msg_id')
    
    # Encrypted data
    nonce = encrypted_data.get('nonce')
    ciphertext = encrypted_data.get('ciphertext')
    
    # Validate session
    if not current_app.sessions.get(session_id):
        return jsonify({'error': 'Invalid session'}), 400
    
    organization = current_app.sessions[session_id].get('organization')
    username = current_app.sessions[session_id].get('username')
    derived_key = current_app.sessions[session_id].get('derived_key')
    
    # Validate signature & decrypt data
    try:
        plaintext_bytes = symmetric.decrypt(derived_key, ciphertext.encode(), nonce.encode(), json.dumps(associated_data).encode())   
    except InvalidTag:
        return jsonify({
            "error": "Encryption failed",
            "derived_key": derived_key,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "associated_data": associated_data
        }), 400

    plaintext = json.loads(plaintext_bytes.decode())

    plaintext_username = plaintext.get('username')
    
    # For a specific subject
    if plaintext_username:
        result = current_app.organization_db.retrieve_subject(organization, plaintext_username)
        return jsonify(f"{result['name'] ({result['state']})}"), 200

    # For all subjects in the organization
    result = current_app.organization_db.retrieve_subjects(organization)
    return jsonify(result.map(lambda x: f"{x['name'] ({x['state']})}")), 200


# Permissions Endpoints
@organization_bp.route('/permissions/<string:permission>/roles', methods=['GET'])
def list_roles_permission(permission):
    # TODO: Logic to get roles that have a given permission
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    roles = current_app.organization_db.retrieve_roles(organization_name)
    documents_metadata = current_app.organization_db.get_metadata(organization_name)

    permission_roles = []
    
    for role, role_data in roles.items():
        if permission in role_data.get('permissions', []):
            permission_roles.append(role)

    
    for document_name, document_metadata in documents_metadata.items():
        for role, acl in document_metadata.get('document_acl', {}).items():
            if permission in acl:
                permission_roles.append(role)

    return jsonify(permission_roles), 200
    

# Documents Endpoints
@organization_bp.route("/documents", methods=['GET'])
def list_documents():
    data = request.get_json()
    associated_data = data.get('associated_data')
    encrypted_data = data.get('encrypted_data')

    if not associated_data or not encrypted_data:
        return jsonify({'error': f'Missing required fields: {associated_data} {encrypted_data}'}), 400
    
    # Associated data
    session_id = associated_data.get('session_id')
    msg_id = associated_data.get('msg_id')

    # Encrypted data
    nonce = encrypted_data.get('nonce')
    ciphertext = encrypted_data.get('ciphertext')

    # Validate session
    if not current_app.sessions.get(session_id):
        return jsonify({'error': 'Invalid session'}), 400

    organization = current_app.sessions[session_id].get('organization')
    username = current_app.sessions[session_id].get('username')
    derived_key = current_app.sessions[session_id].get('derived_key')    

    # Validate signature & decrypt data
    try:
        plaintext_bytes = symmetric.decrypt(derived_key, ciphertext.encode(), nonce.encode(), json.dumps(associated_data).encode())   
    except InvalidTag:
        return jsonify({
            "error": "Encryption failed",
            "derived_key": derived_key,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "associated_data": associated_data
        }), 400

    plaintext = json.loads(plaintext_bytes.decode())

    plaintext_creator = plaintext.get('creator')
    plaintext_date_filter = plaintext.get('date_filter')
    plaintext_date_str = plaintext.get('date')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session_id)

    documents = current_app.organization_db.list_documents(organization_name, plaintext_creator, plaintext_date_filter, plaintext_date_str)

    return jsonify(documents), 200

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
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    subject = request.args.get('subject')

    current_app.organization_db.delete_metadata(organization_name, document_name, subject)

    return jsonify({f'Document "{document_name}" deleted from organization "{organization_name}"'}), 200


@organization_bp.route("/documents/<string:document_name>/acl", methods=['PUT'])
def update_document_acl(document_name):
    # TODO: Logic to update document ACL
    session = request.args.get('session')

    # Get organization name from session
    organization_name = current_app.organization_db.get_organization_name(session)

    data = request.get_json()
    new_acl = data.get('acl') # new_acl example: "tios_de_aveiro": ["DOC_ACL", "DOC_READ"]

    current_app.organization_db.update_acl(organization_name, document_name, new_acl)
    
    return jsonify({f'Document "{document_name}" ACL updated in organization "{organization_name}"'}), 200

