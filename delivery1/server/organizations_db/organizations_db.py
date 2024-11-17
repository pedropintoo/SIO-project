import os
from pymongo import MongoClient

class OrganizationsDB:
    def __init__(self):
         # Get the MongoDB URI from environment variables
        mongo_uri = os.getenv('MONGO_URI')
        # Connect to the MongoDB server
        self.client = MongoClient(mongo_uri)
        # Access the 'organizations' database
        self.db = self.client.organizations
        # Access the 'organizations' collection
        self.collection = self.db.data

        # drop the collection
        self.collection.drop()
 
 
    def get_organization_name(self, session_id):
        # TODO: Logic to get organization name from session
        pass
    
    ### Subject Management ###
    def add_subject(self, organization_name, subject_name, subject_details):
        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"subjects.{subject_name}": subject_details}}
        )
        return result.modified_count
    
    def delete_subject(self, organization_name, subject_name):
        result = self.collection.update_one(
            {"name": organization_name},
            {"$unset": {f"subjects.{subject_name}": ""}}
        )
        return result.modified_count

    def retrieve_subject(self, organization_name, subject_name):
        result = self.collection.find_one(
            {"name": organization_name},
            {"subjects": {subject_name: 1}}
        )
        return result
    
    def retrieve_subjects(self, organization_name):
        result = self.collection.find_one(
            {"name": organization_name},
            {"subjects": 1}
        )
        return result

    def update_subject(self, organization_name, subject_name, subject_data):
        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"subjects.{subject_name}": subject_data}}
        )
        return result.modified_count

    ### Role Management ###
    def add_role(self, organization_name, role_name, role_details):
        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"roles.{role_name}": role_details}}
        )
        return result.modified_count 

    def delete_role(self, organization_name, role_name):
        result = self.collection.update_one(
            {"name": organization_name},
            {"$unset": {f"roles.{role_name}": ""}}
        )
        return result.modified_count

    def retrieve_role(self, organization_name, role_name):
        result = self.collection.find_one(
            {"name": organization_name},
            {"roles": {role_name: 1}}
        )
        return result
    
    def retrieve_roles(self, organization_name):
        result = self.collection.find_one(
            {"name": organization_name},
            {"roles": 1}
        )
        return result

    def update_role(self, organization_name, role_name, role_data):
        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"roles.{role_name}": role_data}}
        )
        return result.modified_count

    ### Organization Management ###
    def in_database(self, organization_name):
        return self.collection.find_one({"name": organization_name}) is not None
    
    def insert_organization(self, organization):
        return self.collection.insert_one(organization)
    
    def get_organization(self, organization_name):
        return self.collection.find_one({"name": organization_name})
    
    def get_all_organizations(self):
        cursor = self.collection.find()
    
        organizations = []
        for org in cursor:
            org['_id'] = str(org['_id'])
            organizations.append(org)

        return organizations
    ### Documents Metadata Management ###
    def insert_metadata(self, organization_name, document_handle, metadata_details):
        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"documents_metadata.{document_handle}": metadata_details}}
        )
        return result.modified_count
    
    def get_metadata(self, organization_name, document_handle):
        result = self.collection.find_one(
            {"name": organization_name},
            {"documents_metadata": {document_handle: 1}}
        )
        return result

    def delete_metadata(self, organization_name, document_handle, subject):
        """Soft delete metadata by setting 'deleter' and 'file_handle' to None"""

        # Build the field path to the specific document metadata
        document_metadata_field = f"documents_metadata.{document_handle}"

        result = self.collection.update_one(
            {
                "name": organization_name,
                f"{document_metadata_field}": {"$exists": True}
            },
            {
                "$set": {
                    f"{document_metadata_field}.deleter": subject,
                    f"{document_metadata_field}.file_handle": None
                }
            }
        )
        return result.modified_count