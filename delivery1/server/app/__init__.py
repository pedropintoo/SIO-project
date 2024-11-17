from flask import Flask
from app.auth import auth_bp
from app.file import file_bp
from app.session import session_bp
from app.organization import organization_bp
from organizations_db.organizations_db import OrganizationsDB
from cryptography.hazmat.primitives.asymmetric import ec

def create_app():
    app = Flask(__name__)

    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(file_bp, url_prefix='/api/v1/files')
    app.register_blueprint(session_bp, url_prefix='/api/v1/sessions')
    app.register_blueprint(organization_bp, url_prefix='/api/v1/organizations')

    # Sessions data structure
    app.sessions = {}
    app.organization_db = OrganizationsDB()
    app.EC_CURVE = ec.SECP256R1()
    app.files_location = 'vault/'
    
    return app
