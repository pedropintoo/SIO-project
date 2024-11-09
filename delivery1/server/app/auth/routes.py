# api path: /api/v1/auth/ 
from . import auth_bp
from flask import request, jsonify
from organizations_db.organizations_db import OrganizationsDB

organization_db = OrganizationsDB()

@auth_bp.route('/organization', methods=['POST'])
def create_organization():
    data = request.get_json()
    
    required_fields = ['organization', 'username', 'name', 'email', 'public_key']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    organization_name, username, name, email, public_key = [data[field] for field in required_fields]
    
    # Use method in_database to check if organization already exists
    if organization_db.in_database(organization_name):
        return jsonify({'error': 'Organization already exists'}), 400
    
    organization = {
        "name": organization_name,  
        "subjects": {
            username: { 
                "name": name,
                "email": email,
                "public_key": public_key,
                "state": "active"
            }
        },
        "roles": {
            "Managers": {
                "subjects": [username],
                "permissions": [
                    "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD",
                    "ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN",
                    "SUBJECT_UP", "DOC_NEW"
                ],
                "state": "active"
            }
        },
        "documents_metadata": {} 
    }
    
    organization_db.insert_organization(organization)
    
    return jsonify({'message': "Organization created successfully"}), 201  

@auth_bp.route('/session', methods=['POST'])
def create_session():
    # TODO: Logic to create a session
    ...

@auth_bp.route('/session/<int:session_id>', methods=['POST'])
def refresh_session_keys(session_id):
    # TODO: Logic to refresh session keys
    ...
