# app/organization/__init__.py
from flask import Blueprint

organization_bp = Blueprint('organization', __name__)

from . import routes 
