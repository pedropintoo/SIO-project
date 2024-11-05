import json
from views.metadata import Metadata, CustomJSONEncoder

class MetadataDB:
    
    def __init__(self, file):
        self.json_file = file

    def in_database(self, data, organization, documentName):
        return organization in data and documentName in data[organization]

    def insert_metadata(self, organization, documentName, metadata: Metadata):
        """Insert metadata into the json file"""

        try:
            with open(self.json_file, 'r+') as file:
                try:
                    data = json.load(file)
                except json.JSONDecodeError:
                    data = {}

                # Initialize nested dictionaries if not present
                if organization not in data:
                    data[organization] = {}
                
                if documentName in data[organization] and Metadata(**data[organization][documentName]).file_handle is not None:
                    raise Exception("Key already exists")
                
                data[organization][documentName] = metadata._asdict()  # Convert metadata to dictionary

                file.seek(0)
                json.dump(data, file, indent=4, cls=CustomJSONEncoder)
                file.truncate()
        except FileNotFoundError:
            with open(self.json_file, 'w') as file:
                data = {organization: {documentName: metadata._asdict()}}
                json.dump(data, file, indent=4, cls=CustomJSONEncoder)

    def get_metadata(self, organization, documentName):
        """Get metadata from the json file"""
        
        try:
            with open(self.json_file, 'r') as file:
                data = json.load(file)
                if self.in_database(data, organization, documentName):
                    return Metadata(**data[organization][documentName])
        except (FileNotFoundError, json.JSONDecodeError):
            pass  # File does not exist or is empty

        return None

    def delete_metadata(self, organization, documentName, subject):
        """Delete metadata from the json file"""

        try:
            with open(self.json_file, 'r+') as file:
                data = json.load(file)
                if self.in_database(data, organization, documentName):
                    data[organization][documentName]['deleter'] = subject
                    data[organization][documentName]['file_handle'] = None
                    file.seek(0)
                    json.dump(data, file, indent=4, cls=CustomJSONEncoder)
                    file.truncate()
                else:
                    raise Exception("Key not found")
        except (FileNotFoundError, json.JSONDecodeError):
            raise Exception("File not found or empty")
