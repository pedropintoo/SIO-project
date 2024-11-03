import json
from views.metadata import Metadata, CustomJSONEncoder

class MetadataDB:
    KEY_FORMAT = "{organization}:{documentName}"
    
    def __init__(self, file):
        self.json_file = file

    def insert_metadata(self, organization, documentName, metadata: Metadata):
        """Insert metadata into the json file"""
        key = self.KEY_FORMAT.format(organization=organization, documentName=documentName)

        try:
            with open(self.json_file, 'r+') as file:
                try:
                    data = json.load(file)
                except json.JSONDecodeError:
                    data = {}

                if key in data and Metadata(**data[key]).file_handle is not None:
                    raise Exception("Key already exists")
                else:
                    data[key] = metadata._asdict()

                file.seek(0) # beginner of the file
                json.dump(data, file, indent=4, cls=CustomJSONEncoder)
                file.truncate()
        except FileNotFoundError:
            with open(self.json_file, 'w') as file:
                data = {key: metadata._asdict()}
                json.dump(data, file, indent=4, cls=CustomJSONEncoder)

    def get_metadata(self, organization, documentName):
        """Get metadata from the json file"""
        key = self.KEY_FORMAT.format(organization=organization, documentName=documentName)

        try:
            with open(self.json_file, 'r') as file:
                data = json.load(file)
                if key in data:
                    return Metadata(**data[key])
        except (FileNotFoundError, json.JSONDecodeError):
            pass  # File does not exist or is empty

        return None

    def delete_metadata(self, organization, documentName, subject):
        """Delete metadata from the json file"""
        key = self.KEY_FORMAT.format(organization=organization, documentName=documentName)

        try:
            with open(self.json_file, 'r+') as file:
                data = json.load(file)
                if key in data:
                    data[key]['deleter'] = subject
                    data[key]['file_handle'] = None
                    file.seek(0)
                    json.dump(data, file, indent=4, cls=CustomJSONEncoder)
                    file.truncate()
                else:
                    raise Exception("Key not found")
        except (FileNotFoundError, json.JSONDecodeError):
            raise Exception("File not found or empty")

