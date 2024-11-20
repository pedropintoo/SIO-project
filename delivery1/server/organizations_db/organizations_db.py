import os
from pymongo import MongoClient
from datetime import datetime

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
        # self.collection.drop()
 
 
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
            {"name": organization_name, f"subjects.{subject_name}": {"$exists": True}},
            {f"subjects.{subject_name}": 1}
        )
        
        result = result.get('subjects', {}).get(subject_name)
        return result
    
    def retrieve_subjects(self, organization_name):
        result = self.collection.find_one(
            {"name": organization_name},
            {"subjects": 1}
        )
        
        result = result.get('subjects', {})
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

    def update_acl(self, organization_name, document_name, new_acl):
         
        # new_acl example: "tios_de_aveiro": ["DOC_ACL", "DOC_READ"]

        # Fetch the current document metadata
        document_acl = self.collection.find_one(
            {"name": organization_name},
            {f"documents_metadata.{document_name}.document_acl": 1}
        )

        # Update or append the new_acl to the document_acl
        for acl_name, acl_permissions in new_acl.items():
            document_acl[acl_name] = acl_permissions

        # Update the document metadata with the new_acl
        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"documents_metadata.{document_name}.document_acl": document_acl}}
        )

        return result.modified_count
    
    def list_documents(self, organization_name, creator, date_filter, date_str):
        # This command lists the documents of the organization with which I have currently a session, 
        # possibly filtered by a subject that created them and by a date (newer than, older than, equal to), expressed in the DD-MM-YYYY format.

        # TODO: try to do the query immediately

        # Retrieve the organization's documents_metadata
        result = self.collection.find_one(
            {"name": organization_name},
            {"documents_metadata": 1}
        )

        if not result:
            return []

        documents_metadata = result.get('documents_metadata', {})
        documents_list = []

        # Parse the date_str into a datetime object if provided
        if date_str:
            try:
                filter_date = datetime.strptime(date_str, '%d-%m-%Y')
            except ValueError:
                # Handle invalid date_str format
                raise ValueError("date_str must be in DD-MM-YYYY format")

        # Iterate over each document and apply the filters
        for doc_id, doc_meta in documents_metadata.items():
            # Filter by creator if specified
            if creator and doc_meta.get('creator') != creator:
                continue

            # Filter by date if specified
            if date_filter and date_str:
                doc_date_str = doc_meta.get('create_date')
                if not doc_date_str:
                    continue
                try:
                    doc_date = datetime.strptime(doc_date_str, '%Y-%m-%d')
                except ValueError:
                    continue  # Skip if create_date format is invalid
                if date_filter == 'newer than' and not (doc_date > filter_date):
                    continue
                elif date_filter == 'older than' and not (doc_date < filter_date):
                    continue
                elif date_filter == 'equal to' and not (doc_date == filter_date):
                    continue

            # Add the document to the list if it passes all filters
            documents_list.append({doc_id: doc_meta})

        return documents_list