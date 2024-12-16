import os
from flask import Flask
from server.app.auth import auth_bp
from server.app.file import file_bp
from server.app.session import session_bp
from server.app.organization import organization_bp
from server.organizations_db.organizations_db import OrganizationsDB
from cryptography.hazmat.primitives.asymmetric import ec
import logging
from datetime import timedelta

def create_app():
    app = Flask(__name__)

    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(file_bp, url_prefix='/api/v1/files')
    app.register_blueprint(session_bp, url_prefix='/api/v1/sessions')
    app.register_blueprint(organization_bp, url_prefix='/api/v1/organizations')

    # Sessions data structure
    app.sessions = {}
    app.SESSION_EXPIRATION_TIME = timedelta(minutes=5)
    app.organization_db = OrganizationsDB()
    app.EC_CURVE = ec.SECP256R1()
    app.files_location = os.getenv('FILES_LOCATION')
    app.MASTER_KEY = os.getenv('MASTER_KEY')
    app.logger = logging.getLogger('app')
    logging.basicConfig(level=logging.DEBUG)
    
    return app
