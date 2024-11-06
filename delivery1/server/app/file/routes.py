# api path: /api/v1/files/ 
from . import file_bp
from flask import request

# get a file by file_handle
@file_bp.route('/<file_handle>', methods=['GET'])
def get_file(file_handle):
    # TODO: Logic to get a file by file_handle
    ...
