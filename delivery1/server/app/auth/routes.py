# api path: /api/v1/auth/ 
from . import auth_bp
from flask import request, jsonify, current_app
from organizations_db.organizations_db import OrganizationsDB
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import base64

@auth_bp.route('/organization', methods=['POST'])
def create_organization():
    data = request.get_json()
    
    required_fields = ['organization', 'username', 'name', 'email', 'public_key']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    organization_name, username, name, email, public_key = [data[field] for field in required_fields]
    
    # Use method in_database to check if organization already exists
    if current_app.organization_db.in_database(organization_name):
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
    
    current_app.organization_db.insert_organization(organization)
    
    return jsonify({'message': "Organization created successfully"}), 200

@auth_bp.route('/session', methods=['POST'])
def create_session():
    data = request.get_json()

    required_fields = ['organization', 'username', 'password', 'session_public_key']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    organization_name, username, password, session_public_key = [data[field] for field in required_fields]

    # Check if organization exists
    if not current_app.organization_db.in_database(organization_name):
        return jsonify({'error': 'Organization does not exist'}), 400
    
    # Get organization data
    organization = current_app.organization_db.get_organization(organization_name)
    if username not in organization['subjects']:
        return jsonify({'error': 'Invalid username'}), 400    
    
    try:
        # Derive client public key from password
        client_password_int = int.from_bytes(password.encode(), 'big')
        client_private_key = ec.derive_private_key(client_password_int, current_app.EC_CURVE, default_backend())
        derived_public_key_bytes = client_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Get stored public key
        stored_public_key_pem = base64.b64decode(organization['subjects'][username]['public_key'])
        stored_public_key = serialization.load_pem_public_key(stored_public_key_pem)
        stored_public_key_bytes = stored_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Compare keys
        if derived_public_key_bytes != stored_public_key_bytes:
            return jsonify({'error': 'Invalid password or mismatched public key'}), 400

        
        # Handshake for a new session
        # - Generate server private/public key pair
        server_private_key = ec.generate_private_key(current_app.EC_CURVE, default_backend())
        server_public_key_bytes = server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # - Decode client's session public key
        session_public_key_pem = base64.b64decode(session_public_key)
        session_public_key = serialization.load_pem_public_key(session_public_key_pem)

        # - Perform ECDH key exchange
        shared_key = server_private_key.exchange(ec.ECDH(), session_public_key)

        # - Derive a shared session key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        
        # Store session details (temporary storage)
        sessions = current_app.sessions
        session_id = len(sessions) + 1
        sessions[session_id] = {
            'organization': organization_name,
            'username': username,
            'derived_key': derived_key
        }
        
        # Respond with session info
        return jsonify({
            'session_id': session_id,
            'public_key': server_public_key_bytes.decode()
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@auth_bp.route('/session/<int:session_id>', methods=['POST'])
def refresh_session_keys(session_id):
    # TODO: Logic to refresh session keys
    ...
