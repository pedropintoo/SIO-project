# api path: /api/v1/auth/ 
from . import auth_bp
from flask import request, jsonify
from organizations_db.organizations_db import OrganizationsDB

organization_db = OrganizationsDB()

@auth_bp.route('/organization', methods=['POST'])
def create_organization():
    # TODO: Logic to create an organization
    data = request.get_json()
    
    required_fields = ['organization', 'username', 'name', 'email', 'public_key_file']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    organization_name, username, name, email, public_key_file = [data[field] for field in required_fields]
    
    # Use method in_database to check if organization already exists
    data = organization_db.get_all_organizations()
    if organization_db.in_database(data, organization_name):
        return jsonify({'error': 'Organization already exists'}), 400

    

    return jsonify({'message': 'Organization created successfully'}), 201


@auth_bp.route('/session', methods=['POST'])
def create_session():
    # TODO: Logic to create a session
    ...

@auth_bp.route('/session/<int:session_id>', methods=['POST'])
def refresh_session_keys(session_id):
    # TODO: Logic to refresh session keys
    ...
