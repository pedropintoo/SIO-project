from flask import Flask
from server.app.auth import auth_bp
from server.app.file import file_bp
from server.app.session import session_bp
from server.app.organization import organization_bp

from server.metadata_db.metadata_db import MetadataDB
from server.organization_db.organization_db import OrganizationDB


def create_app():
    app = Flask(__name__)

    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(file_bp, url_prefix='/api/v1/files')
    app.register_blueprint(session_bp, url_prefix='/api/v1/sessions')
    app.register_blueprint(organization_bp, url_prefix='/api/v1/organizations')

    return app
