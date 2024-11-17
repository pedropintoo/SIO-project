# api path: /api/v1/auth/ 
from . import auth_bp
from flask import request, jsonify
from organizations_db.organizations_db import OrganizationsDB
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

organization_db = OrganizationsDB()
EC_CURVE = ec.SECP256R1()

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
    
    return jsonify({'message': "Organization created successfully"}), 200

@auth_bp.route('/session', methods=['POST'])
def create_session():
    # TODO: Logic to create a session
    data = request.get_json()

    required_fields = ['organization', 'username', 'password', 'session_public_key']

    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    organization_name, username, password, session_public_key = [data[field] for field in required_fields]

    # Check if organization exists
    if not organization_db.in_database(organization_name):
        return jsonify({'error': 'Organization does not exist'}), 400
    
    # Verify the authenticity of the user
    organization = organization_db.get_organization(organization_name)
    
    if not organization:
        return jsonify({'error': 'Organization does not exist'}), 400
    
    if username not in organization['subjects']:
        return jsonify({'error': f"Invalid username" }), 400
    
    password_int = int.from_bytes(password.encode(), 'big')
    private_key = ec.derive_private_key(password_int, EC_CURVE, default_backend())
    public_key_to_compare = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")

    if organization['subjects'][username]['public_key'] != public_key_to_compare:
        return jsonify({'error': f"Invalid password: {organization['subjects'][username]['public_key']} {public_key_to_compare}"}), 400
    
    return jsonify({'message': "Session created successfully"}), 200

@auth_bp.route('/session/<int:session_id>', methods=['POST'])
def refresh_session_keys(session_id):
    # TODO: Logic to refresh session keys
    ...
