# api path: /api/v1/sessions/ 
from . import session_bp
from flask import request, jsonify, current_app
from server.organizations_db.organizations_db import OrganizationsDB
from utils.session import decapsulate_session_data, encapsulate_session_data

@session_bp.route('/roles', methods=['POST'])
def assume_session_role():
    # TODO: Logic to assume a session role
    plaintext, organization_name, username, msg_id, session_id, derived_key_hex = decapsulate_session_data(request.get_json(), current_app.sessions)

    # Update session msg_id
    msg_id += 1
    current_app.sessions[session_id]['msg_id'] = msg_id

    ############################ Logic of the endpoint ############################
    plaintext_role = plaintext.get('role')

    # Check in the database if the username has that role in that organization
    has_role = current_app.organization_db.check_user_role(organization_name, username, plaintext_role)

    if has_role == False:
        return jsonify({'error': 'User does not have the role in the organization'}), 403
    
    current_app.sessions[session_id]['role'] = plaintext_role
    response = {
        'message': 'Role assumed successfully'
    }

    ###############################################################################

    data = encapsulate_session_data(
        response,
        session_id,
        derived_key_hex,
        msg_id
    )

    return jsonify(data), 200




@session_bp.route('/roles', methods=['GET'])
def list_session_roles():
    # TODO: Logic to list session roles
    ...

@session_bp.route('/roles', methods=['DELETE'])
def refresh_session_keys():
    # TODO: Logic to release session roles
    ...
