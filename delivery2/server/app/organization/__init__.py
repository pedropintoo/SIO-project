# app/organizations/__init__.py
from flask import Blueprint

organization_bp = Blueprint('organizations', __name__)

from . import routes 
