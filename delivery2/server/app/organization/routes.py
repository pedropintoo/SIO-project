# api path: /api/v1/organizations/ 
from . import organization_bp
from flask import jsonify, request, current_app
from server.organizations_db.organizations_db import OrganizationsDB
from utils import symmetric
from utils.session import encapsulate_session_data, decapsulate_session_data, session_info_from_file, check_user_permission_in_session
from cryptography.exceptions import InvalidTag
import json
import logging
import datetime
import base64
import os
from bson.objectid import ObjectId
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

@organization_bp.route('/', methods=['GET'])
def list_orgs():
    return jsonify(current_app.organization_db.get_all_organizations()), 200
    
# Roles Endpoints
@organization_bp.route('/roles/subjects', methods=['GET'])
def list_role_subjects():
    # Subjects of a role of the organization with which I have currently a session.
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")

    role_subjects = current_app.organization_db.retrieve_role_subjects(organization, plaintext_role)

    response = {
        "role_subjects": role_subjects
    }

    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

@organization_bp.route('/roles/permissions', methods=['GET'])
def list_role_permissions():
    # Permissions of a role of the organization with which I have currently a session.
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")

    role_permissions = current_app.organization_db.retrieve_role_permissions(organization, plaintext_role)

    response = {
        "role_permissions": role_permissions
    }

    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

@organization_bp.route('/roles', methods=['POST'])
def add_role():
    # TODO: Logic to add a role
    plaintext, organization_name, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "ROLE_NEW", current_app.sessions[session_id], current_app.organization_db)

    if permission_in_session == False:
        return jsonify({'error': 'User does not have a "ROLE_NEW" permission to add a role'}), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")

    role_details = {
        'state': 'active', # not sure if it should be active or suspended
        'subjects': [],
        'permissions': []
    }

    current_app.organization_db.add_role(organization_name, plaintext_role, role_details)
    response = {
        'state': f'Role "{plaintext_role}" added to organization "{organization_name}" successfully'
    }
    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

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
def add_subject():
    plaintext, organization_name, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "SUBJECT_NEW", current_app.sessions[session_id], current_app.organization_db)

    if permission_in_session == False:
        return jsonify({'error': 'User does not have a "SUBJECT_NEW" permission to add a subject'}), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_username = plaintext.get("username")
    plaintext_email = plaintext.get("email")
    plaintext_name = plaintext.get("name")
    plaintext_public_key = plaintext.get("public_key")

    subject_details = {
        'name': plaintext_name,
        'email': plaintext_email,
        'public_key': plaintext_public_key,
        'state': "active"
    }
    current_app.organization_db.add_subject(organization_name, plaintext_username, subject_details)
    response = {
        'state': f'Subject "{plaintext_username}" added to organization "{organization_name}" successfully'
    }
    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

@organization_bp.route('/subjects/roles', methods=['GET'])
def list_subject_roles():
    # Roles of a subject of the organization with which I have currently a session.
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Logic of the endpoint ############################
    plaintext_username = plaintext.get("username")

    subject_roles = current_app.organization_db.retrieve_subject_roles(organization, plaintext_username)

    response = {
        "subject_roles": subject_roles
    }

    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

@organization_bp.route('/subjects/state', methods=['PUT'])
def update_subject_state():
    plaintext, organization_name, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Logic of the endpoint ############################
    plaintext_username = plaintext.get("username")
    plaintext_state = plaintext.get("state")
    subject_data = current_app.organization_db.retrieve_subject(organization_name, plaintext_username)

    if not subject_data:
        response = {
            'error': f'Subject "{plaintext_username}" not found in organization "{organization_name}"'
        }
        code = 404
    else:
        if plaintext_state != 'active' and plaintext_state != 'suspended':
            response = {
                'error': f'Invalid state "{plaintext_state}". State must be "active" or "suspend"'
            }
            code = 400
        else:
            subject_data["state"] = plaintext_state
            
            current_app.organization_db.update_subject(organization_name, plaintext_username, subject_data)
            response = {
                'state': f'Subject "{plaintext_username}" state updated to "{subject_data["state"]}" in organization "{organization_name}"'
            }
            code = 200
    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), code

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
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Logic of the endpoint ############################
    plaintext_username = plaintext.get("username")
    if plaintext_username:
        new_plaintext = current_app.organization_db.retrieve_subject(organization, plaintext_username)
        new_plaintext = {plaintext_username: new_plaintext.get('state')}
    else:
        result = current_app.organization_db.retrieve_subjects(organization)
        
        new_plaintext = {}
        for username, subject_data in result.items():
            new_plaintext[username] = subject_data.get('state')
    ###############################################################################

    data = encapsulate_session_data(
        new_plaintext,
        session_id,
        derived_key_hex,
        msg_id
    )
        
    return jsonify(data), 200

# Permissions Endpoints
@organization_bp.route('/permissions/roles', methods=['GET'])
def list_permission_roles():
    # Roles of the organization with which I have currently a session that have a given permission.
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Logic of the endpoint ############################
    plaintext_permission = plaintext.get("permission")

    permission_roles = current_app.organization_db.retrieve_permission_roles(current_app.logger, organization, plaintext_permission)

    response = {
        "permission_roles": permission_roles
    }

    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

# Documents Endpoints
@organization_bp.route("/documents", methods=['GET'])
def list_documents():
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Logic of the endpoint ############################
    creator = plaintext.get("creator")
    date_filter = plaintext.get("date_filter")
    date_str = plaintext.get("date_str")
    
    metadata = current_app.organization_db.list_documents(organization, creator, date_filter, date_str)
    
    new_plaintext = {}
    for obj in metadata:
        document_handle, document_metadata = next(iter(obj.items()))
        new_plaintext[document_handle] = {
            "name": document_metadata.get("name"),
            "create_date": document_metadata.get("create_date"),
            "creator": document_metadata.get("creator"),
            "file_handle": document_metadata.get("file_handle"),
            "document_acl": document_metadata.get("document_acl"),
            "deleter": document_metadata.get("deleter")
        }
    ###############################################################################

    data = encapsulate_session_data(
        new_plaintext,
        session_id,
        derived_key_hex,
        msg_id
    )
        
    return jsonify(data), 200
    
@organization_bp.route("/documents", methods=['POST'])
def create_document():
    plaintext, organization_name, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Logic of the endpoint ############################
    encryption_file = plaintext.get("encryption_file")
    current_app.logger.debug(f"document_acl: {plaintext.get('document_acl')}")
    document_acl = plaintext.get("document_acl")
    file_handle_hex = plaintext.get("file_handle")
    name = plaintext.get("name")
    key_hex = plaintext.get("key")
    alg = plaintext.get("alg")
    
    encryption_file_bytes = base64.b64decode(encryption_file.encode("utf-8"))
    file_handle_bytes = bytes.fromhex(file_handle_hex)
    key = bytes.fromhex(key_hex)
    
    # TODO: more algorithms??
    if alg == "AES-GCM":
        nonce = encryption_file_bytes[:12]
        data = encryption_file_bytes[12:]
        original_content = symmetric.decrypt(key, nonce, data, None)
    else:
        return jsonify({'error': 'Invalid algorithm'}), 400
        
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(original_content)
    file_content_digest = digest.finalize()
    
    if file_content_digest != file_handle_bytes:
        return jsonify({'error': 'Invalid file handle'}), 400

    key_salt = os.urandom(16)
    master_key_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), # output is 256 bits -> 32 bytes
        length=32,
        salt=key_salt,
        iterations=480000,
    ).derive(current_app.MASTER_KEY.encode("utf-8"))
       
    key_nonce, encrypted_key = symmetric.encrypt(master_key_kdf, key, None)
       
    document_metadata = {
        'name': name,
        'create_date': datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        'creator': username,
        "file_handle": file_handle_hex,
        "document_acl": document_acl,
        "deleter": None,
        "alg": alg,
        "key": encrypted_key.hex(),
        "key_salt": key_salt.hex(),
        "key_nonce": key_nonce.hex(),
    } 
    
    document_handle = ObjectId()
    current_app.organization_db.insert_metadata(organization_name, document_handle, document_metadata)

    with open(f"{current_app.files_location}{file_handle_hex}", "wb") as file:
        file.write(encryption_file_bytes)

    new_plaintext = { 'state': f'Document "{name}" created in organization "{organization_name}"' }
    ###############################################################################

    data = encapsulate_session_data(
        new_plaintext,
        session_id,
        derived_key_hex,
        msg_id
    )
        
    return jsonify(data), 200

@organization_bp.route("/documents/metadata", methods=['GET'])
def get_document_metadata():
    # TODO: Logic to download metadata of a document
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Logic of the endpoint ############################
    document_name = plaintext.get("document_name")
    metadata = current_app.organization_db.get_metadata_by_document_name(organization, document_name)
    document_handle, all_metadata = next(iter(metadata.items()))

    stored_key = bytes.fromhex(all_metadata.get("key"))
    stored_key_salt = bytes.fromhex(all_metadata.get("key_salt"))
    stored_key_nonce = bytes.fromhex(all_metadata.get("key_nonce"))
    stored_alg = all_metadata.get("alg")
    
    master_key_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), # output is 256 bits -> 32 bytes
        length=32,
        salt=stored_key_salt,
        iterations=480000,
    ).derive(current_app.MASTER_KEY.encode("utf-8"))
            
    try:
        key = symmetric.decrypt(master_key_kdf, stored_key_nonce, stored_key, None) 
    
    except InvalidTag:
        return jsonify({'error': f'Invalid tag'}), 400   
    

    # Filter to include only public properties
    new_plaintext = {
        "document_handle": document_handle,
        "name": all_metadata.get("name"),
        "create_date": all_metadata.get("create_date"),
        "creator": all_metadata.get("creator"),
        "file_handle": all_metadata.get("file_handle"),
        "document_acl": all_metadata.get("document_acl"),
        "deleter": all_metadata.get("deleter"),
        "alg": stored_alg,
        "key": key.hex(),
    }

    ###############################################################################

    data = encapsulate_session_data(
        new_plaintext,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

@organization_bp.route("/documents/", methods=['DELETE'])
def delete_document():

    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Logic of the endpoint ############################
    document_name = plaintext.get("document_name")
    metadata = current_app.organization_db.get_metadata_by_document_name(organization, document_name)
    document_handle, all_metadata = next(iter(metadata.items()))
    
    current_app.organization_db.delete_metadata(organization, document_name, username)

    stored_key = bytes.fromhex(all_metadata.get("key"))
    stored_key_salt = bytes.fromhex(all_metadata.get("key_salt"))
    stored_key_nonce = bytes.fromhex(all_metadata.get("key_nonce"))
    stored_alg = all_metadata.get("alg")
    
    master_key_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), # output is 256 bits -> 32 bytes
        length=32,
        salt=stored_key_salt,
        iterations=480000,
    ).derive(current_app.MASTER_KEY.encode("utf-8"))
            
    try:
        key = symmetric.decrypt(master_key_kdf, stored_key_nonce, stored_key, None) 
    
    except InvalidTag:
        return jsonify({'error': f'Invalid tag'}), 400   
    
    # Filter to include only public properties
    new_plaintext = {
        "file_handle": all_metadata.get("file_handle"),
        "alg": stored_alg,
        "key": key.hex(),
    }
    
    ###############################################################################

    data = encapsulate_session_data(
        new_plaintext,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

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

