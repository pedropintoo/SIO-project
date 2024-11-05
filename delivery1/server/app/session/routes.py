# api path: /api/v1/sessions/ 
from . import session_bp

@session_bp.route('/roles', methods=['POST'])
def assume_session_role():
    # TODO: Logic to assume a session role
    ...

@session_bp.route('/roles', methods=['GET'])
def list_session_roles():
    # TODO: Logic to list session roles
    ...

@session_bp.route('/roles', methods=['DELETE'])
def refresh_session_keys():
    # TODO: Logic to release session roles
    ...
