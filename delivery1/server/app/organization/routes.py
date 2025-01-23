# api path: /api/v1/organizations/ 
from . import organization_bp
from flask import jsonify, request, current_app
# from server.organizations_db import check_role_permission, check_role_permission_document
from utils import symmetric
from utils.session import encapsulate_session_data, decapsulate_session_data, session_info_from_file, get_document_handle, get_document_handle
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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")

    role_subjects = current_app.organization_db.retrieve_role_subjects(organization, plaintext_role)
    
    if not role_subjects:
        response = {'error': f'Role "{plaintext_role}" not found in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 404

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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")

    role_permissions = current_app.organization_db.retrieve_role_permissions(organization, plaintext_role)
    
    if not role_permissions:
        response = {'error': f'Role "{plaintext_role}" not found in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 404

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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    permission_in_session = current_app.organization_db.check_role_permission(current_app.sessions[session_id], "ROLE_NEW")

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

    r = current_app.organization_db.add_role(organization, plaintext_role, role_details)
    
    if not r:
        response = {'error': f'Role "{plaintext_role}" already exists in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 409

    response = {
        'state': f'Role "{plaintext_role}" added to organization "{organization}" successfully'
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
#     organization = current_app.organization_db.get_organization_name(session)  

#     role_data = current_app.organization_db.retrieve_role(organization, role) 
#     if not role_data:
#         response = {'error': f'Role "{role}" not found in organization "{organization}"'}
#         data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
#         return jsonify(data), 403
          
#     data = request.get_json()
#     action = data.get('action') 
    
#     if action == 'add':
#         role_data['subjects'].append(data.get('subject'))

#     elif action == 'remove':
#         role_data['subjects'].remove(data.get('subject'))
    
#     current_app.organization_db.update_role(organization, role, role_data)

#     return jsonify({f'Subject "{data.get("subject")}" {action}ed to role "{role}" in organization "{organization}"'}), 200

# @organization_bp.route('/roles/<string:role>/permissions', methods=['POST'])
# def action_permission_to_role(role):
#     session = request.args.get('session')

#     # Get organization name from session
#     organization = current_app.organization_db.get_organization_name(session)

#     role_data = current_app.organization_db.retrieve_role(organization, role)

#     if not role_data:
#         response = {'error': f'Role "{role}" not found in organization "{organization}"'}
        
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

#     current_app.organization_db.update_role(organization, role, role_data)

#     return jsonify({f'Permission "{data.get("permission")}" {action}ed to role "{role}" in organization "{organization}"'}), 200

@organization_bp.route('/roles/suspend', methods=['PUT'])
def suspend_role():
    # Suspends a role in the organization with which I have currently a session. This command requires a ROLE_DOWN permission.
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Can't suspend Managers role ##############################

    # Debugging
    current_app.logger.debug(f"plaintext: {plaintext}")

    if plaintext.get("role") == "Managers":
        response = {'error': 'The Managers role can never be suspended'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    permission_in_session = current_app.organization_db.check_role_permission(current_app.sessions[session_id], "ROLE_DOWN")

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_DOWN" permission to suspend a role'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")

    if not current_app.organization_db.has_one_ROLE_ACL_in_role_after_remove(organization, plaintext_role):
        response = {'error': f'At least one role must have ROLE_ACL permission.'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 409

    role_data = current_app.organization_db.suspend_role(organization, plaintext_role)
    
    if not role_data:
        response = {'error': f'Role "{plaintext_role}" not found in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 404

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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    permission_in_session = current_app.organization_db.check_role_permission(current_app.sessions[session_id], "ROLE_UP")

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_UP" permission to reactivate a role'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")

    role_data = current_app.organization_db.reactivate_role(organization, plaintext_role)
    
    if not role_data:
        response = {'error': f'Role "{plaintext_role}" not found in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 404

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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    permission_in_session = current_app.organization_db.check_role_permission(current_app.sessions[session_id], "ROLE_MOD")

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_MOD" permission to add a permission'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")
    plaintext_permission = plaintext.get("permission")

    if plaintext_permission not in current_app.PERMISSIONS:
        response = {'error': f'Invalid permission "{plaintext_permission}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    r = current_app.organization_db.add_permission_to_role(organization, plaintext_role, plaintext_permission)
    
    if not r:
        response = {'error': f'Permission "{plaintext_permission}" already exists in role "{plaintext_role}" in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 409

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
    try: 
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    permission_in_session = current_app.organization_db.check_role_permission(current_app.sessions[session_id], "ROLE_MOD")

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_MOD" permission to remove a permission'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")
    plaintext_permission = plaintext.get("permission")

    if not current_app.organization_db.has_one_ROLE_ACL_in_role_after_remove(organization, plaintext_role, plaintext_permission):
        response = {'error': f'At least one role must have ROLE_ACL permission.'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 409

    r = current_app.organization_db.remove_permission_from_role(organization, plaintext_role, plaintext_permission)
    
    if not r:
        response = {'error': f'Permission "{plaintext_permission}" not found in role "{plaintext_role}" in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 404

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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    permission_in_session = current_app.organization_db.check_role_permission(current_app.sessions[session_id], "ROLE_MOD")

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_MOD" permission to add a permission'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")
    plaintext_subject = plaintext.get("username")

    r = current_app.organization_db.add_subject_to_role(organization, plaintext_role, plaintext_subject)
    
    if not r:
        response = {'error': f'Subject "{plaintext_subject}" already exists in role "{plaintext_role}" in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 409

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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    permission_in_session = current_app.organization_db.check_role_permission(current_app.sessions[session_id], "ROLE_MOD")

    if permission_in_session == False:
        response = {'error': 'User does not have a "ROLE_MOD" permission to remove a subject'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get("role")
    plaintext_subject = plaintext.get("username")

    if plaintext_role == "Managers" and not current_app.organization_db.has_one_active_user_after_remove(organization, plaintext_role, plaintext_subject):
        response = {'error': f'The Managers role must have at any time an active subject'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 404
        
    r = current_app.organization_db.remove_subject_from_role(organization, plaintext_role, plaintext_subject)
    
    if not r:
        response = {'error': f'Subject "{plaintext_subject}" not found in role "{plaintext_role}" in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 404

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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    permission_in_session = current_app.organization_db.check_role_permission(current_app.sessions[session_id], "SUBJECT_NEW")

    if permission_in_session == False:
        current_app.logger.error(f'User does not have a "SUBJECT_NEW" permission to add a subject')
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
    
    r = current_app.organization_db.add_subject(organization, plaintext_username, subject_details)
    
    if not r:
        response = {'error': f'Subject "{plaintext_username}" already exists in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 409
    
    response = {
        'state': f'Subject "{plaintext_username}" added to organization "{organization}" successfully'
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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_username = plaintext.get("username")

    subject_roles = current_app.organization_db.retrieve_subject_roles(organization, plaintext_username)
    
    if not subject_roles:
        response = {'error': f'Subject "{plaintext_username}" not found in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 404

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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    plaintext_state = plaintext.get('state')

    if plaintext_state == 'active':
        required_permission = "SUBJECT_UP"
    elif plaintext_state == 'suspended': 
        required_permission = "SUBJECT_DOWN"
    else:
        response = {'error': f'Invalid state "{plaintext_state}". State must be "active" or "suspended"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    permission_in_session = current_app.organization_db.check_role_permission(current_app.sessions[session_id], required_permission)
    
    if permission_in_session == False:
        current_app.logger.error(f'User does not have a {required_permission} permission to {plaintext_state} a subject')
        response = {'error': f'User does not have a {required_permission} permission to {plaintext_state} a subject'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    ############################ Logic of the endpoint ############################
    plaintext_username = plaintext.get("username")
    subject_data = current_app.organization_db.retrieve_subject(organization, plaintext_username)

    if plaintext_state == "suspended" and current_app.organization_db.check_user_role(organization, plaintext_username, 'Managers'): 
        response = {'error': f'The Managers can never be suspended"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
        
    if not subject_data:
        response = {'error': f'Subject "{plaintext_username}" not found in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    subject_data["state"] = plaintext_state
    
    r = current_app.organization_db.update_subject(organization, plaintext_username, subject_data)
    
    if not r:
        response = {'error': f'Failed to update state of subject "{plaintext_username}" in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 500
    
    response = {
        'state': f'Subject "{plaintext_username}" state updated to "{subject_data["state"]}" in organization "{organization}"'
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
#     organization = current_app.organization_db.get_organization_name(session)

#     subject_data = current_app.organization_db.retrieve_subject(organization, username)

#     if not subject_data:
#         return jsonify({'error': f'Subject "{username}" not found in organization "{organization}"'}), 404

#     return jsonify({'state': subject_data.get('state')}), 200

@organization_bp.route('/subjects/state', methods=['GET'])
def list_all_subjects_state():
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_username = plaintext.get("username")
    if plaintext_username:
        new_plaintext = current_app.organization_db.retrieve_subject(organization, plaintext_username)
        
        if not new_plaintext:
            response = {'error': f'Subject "{plaintext_username}" not found in organization "{organization}"'}
            data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
            return jsonify(data), 404
        
        new_plaintext = {plaintext_username: new_plaintext.get('state')}
    else:
        result = current_app.organization_db.retrieve_subjects(organization)
        
        if not result:
            response = {'error': 'No subjects found in organization'}
            data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
            return jsonify(data), 404
        
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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    plaintext_permission = plaintext.get("permission")

    permission_roles = current_app.organization_db.retrieve_permission_roles(current_app.logger, organization, plaintext_permission)
    
    if permission_roles == None:
        response = {'error': f'Permission "{plaintext_permission}" not found in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 404

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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Logic of the endpoint ############################
    creator = plaintext.get("creator")
    date_filter = plaintext.get("date_filter")
    date_str = plaintext.get("date_str")
    
    metadata = current_app.organization_db.list_documents(organization, creator, date_filter, date_str)

    new_plaintext = {}
    if metadata != None:
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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    permission_in_session = current_app.organization_db.check_role_permission(current_app.sessions[session_id], "DOC_NEW")

    if permission_in_session == False:
        response = {'error': 'User does not have a "DOC_NEW" permission to create a document'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    ############################ Logic of the endpoint ############################
    encryption_file = plaintext.get("encryption_file")
    # current_app.logger.debug(f"document_acl: {plaintext.get('document_acl')}")
    document_acl = {
        current_app.sessions[session_id]["roles"][0]: ["DOC_ACL", "DOC_READ", "DOC_DELETE"] # the first role can read the file
    }
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
    
    document_handle = get_document_handle(organization, name)
    
    r = current_app.organization_db.insert_metadata(organization, document_handle, document_metadata)
    
    if not r:
        response = {'error': f'Document "{name}" already exists in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 409

    with open(f"{current_app.files_location}{file_handle_hex}", "wb") as file:
        file.write(encryption_file_bytes)

    new_plaintext = { 'state': f'Document "{name}" created in organization "{organization}"' }
    
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

    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    document_name = plaintext.get("document_name")
    permission_in_session = current_app.organization_db.check_role_permission_document(current_app.sessions[session_id], document_name, "DOC_READ")

    if permission_in_session == False:
        response = {'error': 'User does not have a "DOC_READ" permission to read a document'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    ############################ Logic of the endpoint ############################
    metadata = current_app.organization_db.get_metadata_by_document_name(organization, document_name)
    
    if not metadata:
        response = {'error': f'Document "{document_name}" not found in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 404
    
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
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    plaintext_document_name = plaintext.get("document_name")
    permission_in_session = current_app.organization_db.check_role_permission_document(current_app.sessions[session_id], plaintext_document_name, "DOC_DELETE")
    
    if permission_in_session == False:
        response = {'error': 'User does not have a "DOC_DELETE" permission to delete a document'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    ############################ Logic of the endpoint ############################
    metadata = current_app.organization_db.get_metadata_by_document_name(organization, plaintext_document_name)
    
    if not metadata:
        response = {'error': f'Document "{plaintext_document_name}" not found in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 404
    
    document_handle, all_metadata = next(iter(metadata.items()))
    
    r = current_app.organization_db.delete_metadata(organization, plaintext_document_name, username)
    
    if not r:
        response = {'error': f'Document "{plaintext_document_name}" already deleted in organization "{organization}"'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 409

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
    # Changes the ACL of a document by adding (+) or removing (-) a permission for a given role. Use the names previously referred for the permission rights. This commands requires a DOC_ACL permission.
    try:
        plaintext, organization, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)
    except Exception as e:   
        data = f'Error: {e}'
        return jsonify(data), 499
        
    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id


    ############################## Check Active User ##############################
    user_data = current_app.organization_db.retrieve_subject(organization, username)
    
    if user_data['state'] != 'active':
        response = {'error': 'User is not active'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403
    
    ############################ Authorization ############################
    plaintext_document_name = plaintext.get("document_name") 
    permission_in_session = current_app.organization_db.check_role_permission_document(current_app.sessions[session_id], plaintext_document_name, "DOC_ACL")

    if permission_in_session == False:
        response = {'error': 'User does not have a "DOC_ACL" permission to change the ACL of a document'}
        data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
        return jsonify(data), 403

    ############################ Logic of the endpoint ############################
    plaintext_operation = plaintext.get("operation")
    plaintext_role = plaintext.get("role")
    plaintext_permission = plaintext.get("permission")

    if plaintext_operation == "+":
        r = current_app.organization_db.add_permission_to_document(organization, plaintext_document_name, plaintext_role, plaintext_permission)
        
        if not r:
            response = {'error': f'Permission "{plaintext_permission}" already exists in document "{plaintext_document_name}" in organization "{organization}"'}
            data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
            return jsonify(data), 409
        
    elif plaintext_operation == "-":
        
        if not current_app.organization_db.has_one_DOC_ACL_in_document_after_remove(current_app.logger, organization, plaintext_document_name, plaintext_role, plaintext_permission):
            response = {'error': f'At least one role must keep this right (DOC_ACL) for each document, in order to allow an ACL to be updated'}            
            data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
            return jsonify(data), 409
        
        r = current_app.organization_db.remove_permission_from_document(organization, plaintext_document_name, plaintext_role, plaintext_permission)
        
        if not r:
            response = {'error': f'Permission "{plaintext_permission}" does not exist in document "{plaintext_document_name}" in organization "{organization}"'}
            data = encapsulate_session_data(response, session_id, derived_key_hex, msg_id)
            return jsonify(data), 409
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
