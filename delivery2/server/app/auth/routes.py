# api path: /api/v1/auth/ 
from . import auth_bp
from flask import request, jsonify, current_app
from server.organizations_db.organizations_db import OrganizationsDB
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import json

@auth_bp.route('/organization', methods=['POST'])
def create_organization():
    data = request.get_json()
    
    required_fields = ['organization', 'username', 'name', 'email', 'public_key']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    organization_name, username, name, email, public_key = [data[field] for field in required_fields]
        
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
    
    r = current_app.organization_db.insert_organization(organization)
    
    if not r:
        return jsonify({'error': 'Organization already exists'}), 400
        
    password = current_app.MASTER_KEY.encode("utf-8")
    secret_key = ec.derive_private_key(int.from_bytes(password, 'big'), current_app.EC_CURVE, default_backend())
    
    associated_data = {
        'organization': organization_name,
        'username': username,
        'name': name,
        'email': email,
        'public_key': public_key
    }

    associated_data_bytes = json.dumps(associated_data).encode("utf-8")
    associated_data_string = associated_data_bytes.decode("utf-8")
        
    response_signature = secret_key.sign(
        associated_data_bytes,
        ec.ECDSA(hashes.SHA256())
    )
        
    return jsonify({
        'associated_data': associated_data_string,
        'signature': response_signature.hex()
    }), 200
    
@auth_bp.route('/session', methods=['POST'])
def create_session():
    data = request.get_json()
    
    # Get body data
    associated_data = data.get('associated_data')
    signature_hex = data.get('signature')
    organization = associated_data.get('organization')
    username = associated_data.get('username')
    
    client_ephemeral_public_key_pem = associated_data.get('client_ephemeral_public_key')
    client_ephemeral_public_key_bytes = client_ephemeral_public_key_pem.encode("utf-8")
    client_ephemeral_public_key = serialization.load_pem_public_key(client_ephemeral_public_key_bytes, backend=default_backend())
    
    # Get client public key
    result = current_app.organization_db.retrieve_subject(organization, username)
    if result is None:
        return jsonify({'error': 'Invalid organization or username'}), 400

    client_public_key_string = result['public_key']
    client_public_key_pem = client_public_key_string.encode("utf-8")
    client_public_key = serialization.load_pem_public_key(client_public_key_pem, backend=default_backend())
    
    try:
        # Verify signature
        client_public_key.verify(
            bytes.fromhex(signature_hex),
            json.dumps(associated_data).encode("utf-8"),
            ec.ECDSA(hashes.SHA256())
        )
        
        # Generate server ephemeral key pair
        server_ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        server_ephemeral_public_key = server_ephemeral_private_key.public_key().public_bytes(  
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        server_ephemeral_public_key_string = server_ephemeral_public_key.decode("utf-8")
        
        # Perform ECDH key exchange
        shared_key = server_ephemeral_private_key.exchange(ec.ECDH(), client_ephemeral_public_key)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        derived_key_hex = derived_key.hex()
        
        # Prepare response
        session_id = len(current_app.sessions) + 1
        current_app.sessions[session_id] = {
            'organization': organization,
            'username': username,
            'derived_key': derived_key_hex,
            'msg_id': 0,
            'roles': []
        }
        
        associated_data = {
            'session_id': session_id,
            'server_ephemeral_public_key': server_ephemeral_public_key_string
        }
        
        associated_data_bytes = json.dumps(associated_data).encode("utf-8")
        associated_data_string = associated_data_bytes.decode("utf-8")
        
        
        password = current_app.MASTER_KEY.encode("utf-8")
        secret_key = ec.derive_private_key(int.from_bytes(password, 'big'), current_app.EC_CURVE, default_backend())
        
        response_signature = secret_key.sign(
            associated_data_bytes,
            ec.ECDSA(hashes.SHA256())
        )
               
        # Respond with session info
        return jsonify({
            'associated_data': associated_data_string,
            'signature': response_signature.hex()
        }), 200
    
    except InvalidSignature:
        return jsonify({'error': 'Invalid signature'}), 400
    

@auth_bp.route('/session/<int:session_id>', methods=['POST'])
def refresh_session_keys(session_id):
    # TODO: Logic to refresh session keys
    ...
