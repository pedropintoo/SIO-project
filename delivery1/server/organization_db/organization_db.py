import json

class OrganizationDB:

    def __init__(self, file):
        self.json_file = file

    def in_database(self, data, organization):
        return organization in data

    def insert_organization(self, organization_name, details):
        """Insert organization into the json file"""
        try:
            with open(self.json_file, 'r+') as file:
                try:
                    data = json.load(file)
                except json.JSONDecodeError:
                    data = {}
                
                if self.in_database(data, organization_name):
                    raise Exception("Organization already exists")
                
                data[organization_name] = details

                file.seek(0)
                json.dump(data, file, indent=4)
                file.truncate()
        except FileNotFoundError:
            with open(self.json_file, 'w') as file:
                data = {organization_name: details}
                json.dump(data, file, indent=4)

    def get_organization(self, organization_name):
        """Get organization from the json file"""
        try:
            with open(self.json_file, 'r') as file:
                data = json.load(file)
                if self.in_database(data, organization_name):
                    return data[organization_name]
        except (FileNotFoundError, json.JSONDecodeError):
            pass  # File does not exist or is empty

        return None

    def get_all_organizations(self):
        """Get all organizations from the json file"""
        try:
            with open(self.json_file, 'r') as file:
                data = json.load(file)
                return data
        except (FileNotFoundError, json.JSONDecodeError):
            pass
