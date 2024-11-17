# api path: /api/v1/files/ 
from . import file_bp
from flask import request, jsonify, current_app

# get a file by file_handle
@file_bp.route('/<file_handle>', methods=['GET'])
def get_file(file_handle):
    file_content = None
    with open(f"{current_app.files_location}{file_handle}", "rb") as file:
        file_content = file.read()
    
    return jsonify({'file': file_content.decode()}), 200
