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
    plaintext, organization_name, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session("ROLE_NEW", current_app.sessions[session_id], current_app.organization_db)

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_NEW" permission to add a role'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")

    role_details = {
        'state': 'active',
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

# @organization_bp.route('/roles/<string:role>/subjects', methods=['POST'])
# def action_subject_to_role(role):
#     session = request.args.get('session')   

#     # Get organization name from session
#     organization_name = current_app.organization_db.get_organization_name(session)  

#     role_data = current_app.organization_db.retrieve_role(organization_name, role) 
#     if not role_data:
#         response = {'error': f'Role "{role}" not found in organization "{organization_name}"'}
#         data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
#         return jsonify(data), 403
          
#     data = request.get_json()
#     action = data.get('action') 
    
#     if action == 'add':
#         role_data['subjects'].append(data.get('subject'))

#     elif action == 'remove':
#         role_data['subjects'].remove(data.get('subject'))
    
#     current_app.organization_db.update_role(organization_name, role, role_data)

#     return jsonify({f'Subject "{data.get("subject")}" {action}ed to role "{role}" in organization "{organization_name}"'}), 200

# @organization_bp.route('/roles/<string:role>/permissions', methods=['POST'])
# def action_permission_to_role(role):
#     session = request.args.get('session')

#     # Get organization name from session
#     organization_name = current_app.organization_db.get_organization_name(session)

#     role_data = current_app.organization_db.retrieve_role(organization_name, role)

#     if not role_data:
#         response = {'error': f'Role "{role}" not found in organization "{organization_name}"'}
        
#         data = encapsulate_session_data(
#             response,
#             session_id,
#             derived_key_hex,
#             msg_id
#         )

#         return jsonify(data), 403

#     data = request.get_json()
#     action = data.get('action')    

#     if action == 'add':
#         role_data['permissions'].append(data.get('permission'))
#     elif action == 'remove':
#         role_data['permissions'].remove(data.get('permission'))

#     current_app.organization_db.update_role(organization_name, role, role_data)

#     return jsonify({f'Permission "{data.get("permission")}" {action}ed to role "{role}" in organization "{organization_name}"'}), 200

@organization_bp.route('/roles/suspend', methods=['PUT'])
def suspend_role():
    # Suspends a role in the organization with which I have currently a session. This command requires a ROLE_DOWN permission.
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "ROLE_DOWN", current_app.sessions[session_id], current_app.organization_db)

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_DOWN" permission to suspend a role'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")

    role_data = current_app.organization_db.suspend_role(organization, plaintext_role)

    response = {
        'state': f'Role "{plaintext_role}" suspended in organization "{organization}"'
    }

    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

@organization_bp.route('/roles/reactivate', methods=['PUT'])
def reactivate_role():
    # Reactivate a role in the organization with which I have currently a session. This command requires a ROLE_UP permission.
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "ROLE_UP", current_app.sessions[session_id], current_app.organization_db)

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_UP" permission to reactivate a role'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")

    role_data = current_app.organization_db.reactivate_role(organization, plaintext_role)

    response = {
        'state': f'Role "{plaintext_role}" reactivate in organization "{organization}"'
    }

    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

@organization_bp.route('/roles/permissions', methods=['POST'])
def add_permission_to_role():
    # Add a permission to a role of the organization with which I have currently a session. This command requires a ROLE_MOD permission.
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "ROLE_MOD", current_app.sessions[session_id], current_app.organization_db)

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_MOD" permission to add a permission'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")
    plaintext_permission = plaintext.get("permission")

    current_app.organization_db.add_permission_to_role(organization, plaintext_role, plaintext_permission)

    response = {
        'state': f'Permission "{plaintext_permission}" added to role "{plaintext_role}" in organization "{organization}"'
    }

    ###############################################################################
    
    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

@organization_bp.route('/roles/permissions', methods=['DELETE'])
def remove_permission_from_role():
    # Remove a permission from a role of the organization with which I have currently a session. This command requires a ROLE_MOD permission.
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "ROLE_MOD", current_app.sessions[session_id], current_app.organization_db)

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_MOD" permission to remove a permission'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")
    plaintext_permission = plaintext.get("permission")

    current_app.organization_db.remove_permission_from_role(organization, plaintext_role, plaintext_permission)

    response = {
        'state': f'Permission "{plaintext_permission}" removed from role "{plaintext_role}" in organization "{organization}"'
    }

    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

@organization_bp.route('/roles/subjects', methods=['POST'])
def add_subject_to_role():
    # Add a subject to a role of the organization with which I have currently a session. This command requires a ROLE_MOD permission.
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "ROLE_MOD", current_app.sessions[session_id], current_app.organization_db)

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_MOD" permission to add a permission'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")
    plaintext_subject = plaintext.get("username")

    current_app.organization_db.add_subject_to_role(organization, plaintext_role, plaintext_subject)

    response = {
        'state': f'Subject "{plaintext_subject}" added to role "{plaintext_role}" in organization "{organization}"'
    }

    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

@organization_bp.route('/roles/subjects', methods=['DELETE'])
def remove_subject_from_role():
    # Remove a subject from a role of the organization with which I have currently a session. This command requires a ROLE_MOD permission.
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "ROLE_MOD", current_app.sessions[session_id], current_app.organization_db)

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_MOD" permission to remove a subject'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")
    plaintext_subject = plaintext.get("username")

    current_app.organization_db.remove_subject_from_role(organization, plaintext_role, plaintext_subject)

    response = {
        'state': f'Subject "{plaintext_subject}" removed from role "{plaintext_role}" in organization "{organization}"'
    }

    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

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
        response = {'error': 'User does not have a "SUBJECT_NEW" permission to add a subject'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
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
        response = {'error': f'Subject "{plaintext_username}" not found in organization "{organization_name}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    if plaintext_state != 'active' and plaintext_state != 'suspended':
        response = {'error': f'Invalid state "{plaintext_state}". State must be "active" or "suspend"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    subject_data["state"] = plaintext_state
    
    current_app.organization_db.update_subject(organization_name, plaintext_username, subject_data)
    response = {
        'state': f'Subject "{plaintext_username}" state updated to "{subject_data["state"]}" in organization "{organization_name}"'
    }
    
    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200

# @organization_bp.route('/subjects/<string:username>/state', methods=['GET'])
# def list_subject_state(username):
#     session = request.args.get('session')

#     # Get organization name from session
#     organization_name = current_app.organization_db.get_organization_name(session)

#     subject_data = current_app.organization_db.retrieve_subject(organization_name, username)

#     if not subject_data:
#         return jsonify({'error': f'Subject "{username}" not found in organization "{organization_name}"'}), 404

#     return jsonify({'state': subject_data.get('state')}), 200

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

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "DOC_NEW", current_app.sessions[session_id], current_app.organization_db)

    if permission_in_session == False:
        response = {'error': 'User does not have a "DOC_NEW" permission to create a document'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

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
        response = {'error': 'Invalid algorithm'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 400
        
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(original_content)
    file_content_digest = digest.finalize()
    
    if file_content_digest != file_handle_bytes:
        response = {'error': 'Invalid file handle'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 400

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
    # Fetches the metadata of a document with a given name to the organization with which I have currently a session. The output of this command is useful for getting the clear text contents of a document’s file. This commands requires a DOC_READ permission.

    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "DOC_READ", current_app.sessions[session_id], current_app.organization_db)

    if permission_in_session == False:
        response = {'error': 'User does not have a "DOC_READ" permission to read a document'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

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
        response = {'error': f'Invalid tag'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 400    

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
    # clears file_handle in the metadata of a document with a given name on the organization with which I have currently a session. The output of this command is the file_handle that ceased to exist in the document’s metadata. This commands requires a DOC_DELETE permission.

    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "DOC_DELETE", current_app.sessions[session_id], current_app.organization_db)
    
    if permission_in_session == False:
        response = {'error': 'User does not have a "DOC_DELETE" permission to delete a document'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

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
        response = {'error': f'Invalid tag'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 400   
    
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

@organization_bp.route("/documents/acl", methods=['POST'])
def update_acl_doc():
    # changes the ACL of a document by adding (+) or removing (-) a permission for a given role. Use the names previously referred for the permission rights. This commands requires a DOC_ACL permission.
    plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Authorization ############################
    permission_in_session = check_user_permission_in_session( "DOC_ACL", current_app.sessions[session_id], current_app.organization_db )

    if permission_in_session == False:
        response = {'error': 'User does not have a "DOC_ACL" permission to change the ACL of a document'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    ############################ Logic of the endpoint ############################
    plaintext_document_name = plaintext.get("document_name")
    plaintext_operation = plaintext.get("operation")
    plaintext_role = plaintext.get("role")
    plaintext_permission = plaintext.get("permission")

    if plaintext_operation == "+":
        current_app.organization_db.add_permission_to_document(organization, plaintext_document_name, plaintext_role, plaintext_permission)
    elif plaintext_operation == "-":
        current_app.organization_db.remove_permission_from_document(organization, plaintext_document_name, plaintext_role, plaintext_permission)
    else:
        response = {'error': 'Invalid operation. Operation must be "+" or "-"'}

        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    response = {
        'state': f'ACL of document "{plaintext_document_name}" updated in organization "{organization}"'
    }

    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )
    
    return jsonify(data), 200
