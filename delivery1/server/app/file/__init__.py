# app/file/__init__.py
from flask import Blueprint

file_bp = Blueprint('file', __name__)

from . import routes 
