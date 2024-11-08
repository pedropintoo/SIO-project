# run.py
from server.app import create_app
from server.organization_db.organization_db import OrganizationDB

class AppFlask:
    def __init__(self):
        self.app = create_app()
        self.app.run(debug=True)
