from flask import Flask
from app.auth import auth_bp
from app.session import session_bp
from app.organization import organization_bp

def create_app():
    app = Flask(__name__)

    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(session_bp, url_prefix='/api/v1/session')
    app.register_blueprint(organization_bp, url_prefix='/api/v1/organizations')

    return app
