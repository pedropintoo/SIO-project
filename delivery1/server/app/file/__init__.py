# app/files/__init__.py
from flask import Blueprint

file_bp = Blueprint('files', __name__)

from . import routes 
