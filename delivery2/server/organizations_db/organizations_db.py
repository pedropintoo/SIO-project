import os
from pymongo import MongoClient
from datetime import datetime
from utils.session import get_document_handle

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
        organization = self.collection.find_one({"name": organization_name})

        if not organization:
            return None
        
        subjects = organization.get('subjects', {})

        # Check if subject already exists, if so, return None
        if subject_name in subjects:
            return None

        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"subjects.{subject_name}": subject_details}}
        )

        if not result:
            return None

        return result.modified_count
    
    def delete_subject(self, organization_name, subject_name):
                
        if not self.collection.find_one({"name": organization_name, f"subjects.{subject_name}": {"$exists": True}}):
            return None
        
        result = self.collection.update_one(
            {"name": organization_name},
            {"$unset": {f"subjects.{subject_name}": ""}}
        )

        if not result:
            return None

        return result.modified_count    

    def retrieve_subject(self, organization_name, subject_name):
        result = self.collection.find_one(
            {"name": organization_name, f"subjects.{subject_name}": {"$exists": True}},
            {f"subjects.{subject_name}": 1}
        )
        
        if not result:
            return None

        result = result.get('subjects', {}).get(subject_name)
        return result
    
    def retrieve_subjects(self, organization_name):
        result = self.collection.find_one(
            {"name": organization_name},
            {"subjects": 1}
        )
        
        if not result:
            return None

        result = result.get('subjects', {})
        return result

    def update_subject(self, organization_name, subject_name, subject_data):
        
        if not self.collection.find_one({"name": organization_name, f"subjects.{subject_name}": {"$exists": True}}):
            return None
        
        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"subjects.{subject_name}": subject_data}}
        )

        if not result:
            return None

        return result.modified_count

    ### Role Management ###
    def add_role(self, organization_name, role_name, role_details):
        organization = self.collection.find_one({"name": organization_name})

        if not organization:
            return None
        
        roles = organization.get('roles', {})

        if role_name in roles:
            return None

        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"roles.{role_name}": role_details}}
        )
        
        return result.modified_count 

    def delete_role(self, organization_name, role_name):
        
        if not self.collection.find_one({"name": organization_name, f"roles.{role_name}": {"$exists": True}}):
            return None
        
        result = self.collection.update_one(
            {"name": organization_name},
            {"$unset": {f"roles.{role_name}": ""}}
        )

        if not result:
            return None

        return result.modified_count

    def retrieve_role(self, organization_name, role_name):
        result = self.collection.find_one(
            {"name": organization_name},
            {"roles": {role_name: 1}}
        )

        if not result:
            return None

        return result
    
    def retrieve_roles(self, organization_name):
        result = self.collection.find_one(
            {"name": organization_name},
            {"roles": 1}
        )

        if not result:
            return None

        return result
    
    def retrieve_role_subjects(self, organization_name, role_name):
        result = self.collection.find_one(
            {"name": organization_name},
            {"roles": {role_name: 1}}
        )

        if not result:
            return None

        result = result.get('roles', {}).get(role_name, {}).get('subjects', [])
        
        if not result:
            return None

        return result

    def retrieve_subject_roles(self, organization_name, username):
        result = self.collection.find_one(
            {"name": organization_name},
            {"roles": 1}
        )
        
        if not result:
            return None

        all_roles = result.get('roles', {})

        subject_roles = []
        for role_name, role_data in all_roles.items():
            if username in role_data.get('subjects', []):
                subject_roles.append(role_name)
            
        return subject_roles
    
    def retrieve_role_permissions(self, organization_name, role_name):
        result = self.collection.find_one(
            {"name": organization_name},
            {"roles": {role_name: 1}}
        )

        if not result:
            return None

        result = result.get('roles', {}).get(role_name, {}).get('permissions', [])
        
        if not result:
            return None

        return result

    def retrieve_permission_roles(self, logger, organization_name, permission):
        result = self.collection.find_one(
            {"name": organization_name},
            {"roles": 1}
        )
        
        if not result:
            return None

        all_roles = result.get('roles', {})

        permission_roles = []
        for role_name, role_data in all_roles.items():
            if permission in role_data.get('permissions', []):
                permission_roles.append(role_name)

        # As roles can be used in documents’ ACLs to associate subjects to permissions, 
        # this command should also list the roles per document that have the given permission.
        result = self.collection.find_one(
            {"name": organization_name},
            {"documents_metadata": 1}
        )

        logger.info(f"Documents metadata: {result}")

        if not result:
            return None
        
        # TODO: Not sure if this is the correct way to do
        documents_metadata = result.get('documents_metadata', {})
        for doc_meta in documents_metadata.values():
            doc_acl = doc_meta.get('document_acl', {})
            logger.info(f"Document ACL: {doc_acl}")
            for acl_name, acl_permissions in doc_acl.items():
                logger.info(f"ACL: {acl_name}")
                logger.info(f"ACL permissions: {acl_permissions}")
                if permission in acl_permissions:
                    permission_roles.append((doc_meta.get('name'), acl_name))

        return permission_roles

    def update_role(self, organization_name, role_name, role_data):

        if not self.collection.find_one({"name": organization_name, f"roles.{role_name}": {"$exists": True}}):
            return None

        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"roles.{role_name}": role_data}}
        )

        if not result:
            return None

        return result.modified_count

    def check_user_role(self, organization_name, username, role_name):
        """Check if a user is part of a specific role in an organization."""
        organization = self.collection.find_one({"name": organization_name})

        if not organization:
            return False
        
        role = organization.get('roles', {}).get(role_name)
        if not role:
            return False

        return username in role.get('subjects', [])

    def check_role_permission(self, session, permission):
        """Check if any of the specified roles have the given permission in an organization."""
        username, organization_name, roles_session = session['username'], session['organization'], session['roles']  
        
        organization = self.collection.find_one({"name": organization_name})
        
        if not organization:
            return False  
        
        all_roles = organization.get('roles', {})
                
        for role_session in roles_session:
            role_information = all_roles.get(role_session)
            if permission in role_information.get('permissions', []) and role_information.get('state') == 'active' and username in role_information.get('subjects', []):
                return True
            
        return False

    def check_role_permission_document(self, session, document_name, permission):
        """Check in documents_metadata if the role in document_acl has the given permission in an organization."""
        username, organization_name, roles_session = session['username'], session['organization'], session['roles']
        
        organization = self.collection.find_one({"name": organization_name})
        
        if not organization:
            return False

        document_handle = get_document_handle(organization_name, document_name)
        document_acl = organization.get('documents_metadata', {}).get(document_handle, {}).get('document_acl', {})

        all_roles = organization.get('roles', {})

        for role_session in roles_session:
            role_information = all_roles.get(role_session)
            role_permissions = document_acl.get(role_session, [])
            if permission in role_permissions and role_information.get('state') == 'active' and username in role_information.get('subjects', []):
                return True
                
        return False
    
    # Auxiliary function
    def role_state(self, organization, role_name):
        # Returns the state of a role inside a previously fetched organization
        return organization.get('roles', {}).get(role_name, {}).get('state')
        
    def suspend_role(self, organization_name, role_name):
        if not self.collection.find_one({"name": organization_name, f"roles.{role_name}": {"$exists": True}}):
            return None

        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"roles.{role_name}.state": "suspended"}}
        )

        if not result:
            return None

        return result.modified_count
    
    def reactivate_role(self, organization_name, role_name):
        if not self.collection.find_one({"name": organization_name, f"roles.{role_name}": {"$exists": True}}):
            return None

        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"roles.{role_name}.state": "active"}}
        )

        if not result:
            return None

        return result.modified_count
    
    def add_permission_to_role(self, organization_name, role_name, permission):
        if not self.collection.find_one({"name": organization_name, f"roles.{role_name}": {"$exists": True}}):
            return None

        result = self.collection.update_one(
            {"name": organization_name},
            {"$push": {f"roles.{role_name}.permissions": permission}}
        )

        if not result:
            return None

        return result.modified_count
    
    def remove_permission_from_role(self, organization_name, role_name, permission):
        if not self.collection.find_one({"name": organization_name, f"roles.{role_name}": {"$exists": True}}):
            return None

        result = self.collection.update_one(
            {"name": organization_name},
            {"$pull": {f"roles.{role_name}.permissions": permission}}
        )

        if not result:
            return None

        return result.modified_count

    def add_subject_to_role(self, organization_name, role_name, subject):
        if not self.collection.find_one({"name": organization_name, f"roles.{role_name}": {"$exists": True}}):
            return None
            
        result = self.collection.update_one(
            {"name": organization_name},
            {"$push": {f"roles.{role_name}.subjects": subject}}
        )

        if not result:
            return None

        return result.modified_count
    
    def remove_subject_from_role(self, organization_name, role_name, subject):
        if not self.collection.find_one({"name": organization_name, f"roles.{role_name}": {"$exists": True}}):
            return None
        
        result = self.collection.update_one(
            {"name": organization_name},
            {"$pull": {f"roles.{role_name}.subjects": subject}}
        )

        if not result:
            return None

        return result.modified_count

    def has_one_active_user_after_remove(self, organization_name, role_name, subject):
        result = self.collection.find_one(
            {"name": organization_name},
            {"roles": 1, "subjects": 1}  # Only fetch roles and subjects
        )
        if not result:
            return None  # Organization not found

        roles = result.get("roles", {})
        role = roles.get(role_name)
        if not role:
            return None  # Role not found

        role_subjects = role.get("subjects", [])
        if subject_to_remove not in role_subjects:
            return None  # The subject to remove is not part of the role

        remaining_subjects = [subj for subj in role_subjects if subj != subject_to_remove]

        subjects = result.get("subjects", {})
        for subj_id in remaining_subjects:
            subject = subjects.get(subj_id)
            if subject and subject.get("state") == "active":
                return True  # At least one remaining subject is active

        return False

    ### Organization Management ###
    def in_database(self, organization_name):
        return self.collection.find_one({"name": organization_name}) is not None
    
    def insert_organization(self, organization):
        # Check if the organization already exists
        
        if self.in_database(organization.get("name")):
            return None  # Organization already exists
        
        return self.collection.insert_one(organization)
    
    def get_organization(self, organization_name):
        result = self.collection.find_one({"name": organization_name})
        if not result:
            return None
        return result

    def get_all_organizations(self):
        cursor = self.collection.find()
    
        organizations = []
        for org in cursor:
            org['_id'] = str(org['_id'])
            organizations.append(org)

        return organizations

    ### Documents Metadata Management ###

    def insert_metadata(self, organization_name, document_handle, metadata_details):
        if self.collection.find_one({"name": organization_name, f"documents_metadata.{document_handle}": {"$exists": True}}):
            return None

        result = self.collection.update_one(
            {"name": organization_name},
            {"$set": {f"documents_metadata.{document_handle}": metadata_details}}
        )

        if not result:
            return None

        return result.modified_count
    
    def get_metadata(self, organization_name, document_handle):       
        result = self.collection.find_one(
            {"name": organization_name},
            {"documents_metadata": {document_handle: 1}}
        )

        if not result:
            return None

        return result

    def get_metadata_by_document_name(self, organization_name, document_name):
        # Use an aggregation pipeline to find the document with the given name
        # pipeline = [
        #     {"$match": {"name": organization_name}},  # Match the organization
        #     {
        #         "$project": {
        #             "metadata": {
        #                 "$filter": {
        #                     "input": {"$objectToArray": "$documents_metadata"},  # Convert documents_metadata to an array
        #                     "as": "doc",
        #                     "cond": {"$eq": ["$$doc.v.name", document_name]}  # Match the document name
        #                 }
        #             }
        #         }
        #     }
        # ]

        # result = list(self.collection.aggregate(pipeline))

        # if not result or not result[0]["metadata"]:
        #     return None  # Organization or document not found

        # # Return the document_handle along with its metadata
        # doc = result[0]["metadata"][0]
        # return {doc["k"]: doc["v"]}

        # TODO: Test

        document_handle = get_document_handle(organization_name, document_name)
        
        result = self.collection.find_one(
            {"name": organization_name},
            {"documents_metadata": {document_handle: 1}}
        )

        if not result or not result.get('documents_metadata'):
            return None
        
        # Return the document_handle along with its metadata
        doc = result["documents_metadata"][document_handle]
        return {document_handle: doc}


    def delete_metadata(self, organization_name, document_name, subject):
        # """Soft delete metadata by setting 'deleter' and 'file_handle' to None"""

        # print("organization_name", organization_name)
        # pipeline = [
        #     {"$match": {"name": organization_name}},  # Match the organization
        #     {
        #         "$project": {
        #             "metadata": {
        #                 "$filter": {
        #                     "input": {"$objectToArray": "$documents_metadata"},  # Convert documents_metadata to an array
        #                     "as": "doc",
        #                     "cond": {"$eq": ["$$doc.v.name", document_name]}  # Match the document name
        #                 }
        #             }
        #         }
        #     }
        # ]

        # result = list(self.collection.aggregate(pipeline))

        # if not result or not result[0]["metadata"]:
        #     return False  # Organization or document not found

        # # Extract the document handle
        # document_handle = result[0]["metadata"][0]["k"]

        # # Perform the soft delete by updating the document
        # update_result = self.collection.update_one(
        #     {"name": organization_name},  # Match the organization
        #     {
        #         "$set": {
        #             f"documents_metadata.{document_handle}.deleter": subject,
        #             f"documents_metadata.{document_handle}.file_handle": None,
        #         }
        #     }
        # )

        # # Return True if the update modified a document, otherwise False
        # return update_result.modified_count > 0

        # TODO: Test

        document_handle = get_document_handle(organization_name, document_name)
        
        if not self.collection.find_one({"name": organization_name, f"documents_metadata.{document_handle}": {"$exists": True}}):
            return None
        
        # Perform the soft delete by updating the document
        update_result = self.collection.update_one(
            {"name": organization_name},
            {
                "$set": {
                    f"documents_metadata.{document_handle}.deleter": subject,
                    f"documents_metadata.{document_handle}.file_handle": None,
                }
            }
        )

        if not update_result:
            return None

        return update_result.modified_count > 0



    # def update_acl(self, organization_name, document_name, new_acl):
         
    #     # new_acl example: "tios_de_aveiro": ["DOC_ACL", "DOC_READ"]

    #     # Fetch the current document metadata
    #     document_acl = self.collection.find_one(
    #         {"name": organization_name},
    #         {f"documents_metadata.{document_name}.document_acl": 1}
    #     )

    #     # Update or append the new_acl to the document_acl
    #     for acl_name, acl_permissions in new_acl.items():
    #         document_acl[acl_name] = acl_permissions

    #     # Update the document metadata with the new_acl
    #     result = self.collection.update_one(
    #         {"name": organization_name},
    #         {"$set": {f"documents_metadata.{document_name}.document_acl": document_acl}}
    #     )

    #     return result.modified_count

    def add_permission_to_document(self, organization_name, document_name, role_name, permission):
        # TODO: Test

        # Add a permission for a given role.
        document_handle = get_document_handle(organization_name, document_name) # TODO: Test
        
        if not self.collection.find_one({"name": organization_name, f"documents_metadata.{document_handle}": {"$exists": True}}):
            return None
        
        result = self.collection.update_one(
            {"name": organization_name},
            {"$push": {f"documents_metadata.{document_handle}.document_acl.{role_name}": permission}}
        )

        if not result:
            return None

        return result.modified_count
    
    def remove_permission_from_document(self, organization_name, document_name, role_name, permission):
        # TODO: Test
        
        # Remove a permission for a given role.
        document_handle = get_document_handle(organization_name, document_name) # TODO:
        
        if not self.collection.find_one({"name": organization_name, f"documents_metadata.{document_handle}": {"$exists": True}}):
            return None
        
        result = self.collection.update_one(
            {"name": organization_name},
            {"$pull": {f"documents_metadata.{document_name}.document_acl.{role_name}": permission}}
        )

        if not result:
            return None

        return result.modified_count
    
    def list_documents(self, organization_name, creator, date_filter, date_str):
        # This command lists the documents of the organization with which I have currently a session, 
        # possibly filtered by a subject that created them and by a date (newer than, older than, equal to), expressed in the DD-MM-YYYY format.
        
        # Retrieve the organization's documents_metadata
        result = self.collection.find_one(
            {"name": organization_name},
            {"documents_metadata": 1}
        )

        if not result:
            return None

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
                    doc_date = datetime.strptime(doc_date_str, '%d-%m-%Y %H:%M:%S')
                except ValueError:
                    continue  # Skip if create_date format is invalid
                if date_filter == 'nt' and not (doc_date > filter_date):
                    continue
                elif date_filter == 'ot' and not (doc_date < filter_date):
                    continue
                elif date_filter == 'et' and not (doc_date.date() == filter_date.date()):
                    continue

            # Add the document to the list if it passes all filters
            documents_list.append({doc_id: doc_meta})

        return documents_list

