# api path: /api/v1/files/ 
from . import file_bp
from flask import request, jsonify, current_app
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
import json

# get a file by file_handle
@file_bp.route('/', methods=['GET'])
def get_file():
    data = request.get_json()
    file_handle = data.get('file_handle')
    
    file_content = None
    try:
        with open(f"{current_app.files_location}{file_handle}", "rb") as file:
            file_content = file.read()
        file_content_string = base64.b64encode(file_content).decode("utf-8")
    except Exception as e:
        return jsonify({'error': 'File not found'}), 404
    
    password = current_app.MASTER_KEY.encode("utf-8")
    secret_key = ec.derive_private_key(int.from_bytes(password, 'big'), current_app.EC_CURVE, default_backend())
    
    associated_data = {
        'file_handle': file_handle,
        'file_content': file_content_string
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
