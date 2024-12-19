#!/bin/bash

## !WARNING! ## 

# This script only works if the server is running on the same machine and on the default port (5000)
# docker compose up in `delivery2` folder to start the server

## !WARNING! ##

cd ..
python3 subject.py -k server/rep_pub.pem -r "http://127.0.0.1:5000" > /dev/null 2>&1
cd commands

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

run_test() {
    local expect_failure="$1"
    local test_name="$2"
    shift 2
    echo ""
    echo "$test_name ---------------------------------------------------------------------------"
    "$@"
    local exit_code=$?
    if [ "$expect_failure" = "success" ]; then
        if [ $exit_code -ne 0 ]; then
            echo -e "${RED}Test failed: $test_name${NC}"
            exit 1
        fi
    else
        if [ $exit_code -eq 0 ]; then
            echo -e "${RED}Test failed (expected failure but succeeded): $test_name${NC}"
            exit 1
        fi
    fi
}

run_test_output() {
    local expect_failure="$1"
    local expected_output="$2"
    local test_name="$3"
    shift 3
    echo ""
    echo "$test_name ---------------------------------------------------------------------------"
    output=$("$@" 2>&1)
    local exit_code=$?
    if [ "$expect_failure" = "success" ]; then
        if [ $exit_code -ne 0 ]; then
            echo -e "${RED}Test failed: $test_name${NC}"
            echo -e "$output"
            exit 1
        elif ! echo "$output" | grep -q "$expected_output"; then
            echo -e "${RED}Test failed: $test_name - Output does not contain expected text${NC}"
            echo -e "$output"
            exit 1
        fi
    else
        if [ $exit_code -eq 0 ]; then
            echo -e "${RED}Test failed (expected failure but succeeded): $test_name${NC}"
            echo -e "$output"
            exit 1
        elif echo "$output" | grep -q "$expected_output"; then
            echo -e "${RED}Test failed: $test_name - Output contains unexpected text${NC}"
            echo -e "$output"
            exit 1
        fi
    fi
    echo -e "$output"
}

# Example usage
# run_test_output "Check output of command" "Expected output" ./rep_command arg1 arg2

random_seed=$RANDOM

organization_name="org_$random_seed"
organization_name_2="org_2_$random_seed"
organization_name_3="org_3_$random_seed"

username="user_$random_seed"
full_name="name_$random_seed"
user_password="user_password_$random_seed"
user_credentials="state/user_credentials_$random_seed.pem"
email="email_$random_seed"

username_2="user_2_$random_seed"
full_name_2="name_2_$random_seed"
user_password_2="user_password_2_$random_seed"
user_credentials_2="state/user_credentials_2_$random_seed.pem"
email_2="email_2_$random_seed"

username_3="user_3_$random_seed"
full_name_3="name_3_$random_seed"
user_password_3="user_password_3_$random_seed"
user_credentials_3="state/user_credentials_3_$random_seed.pem"
email_3="email_3_$random_seed"

username_4="user_4_$random_seed"
full_name_4="name_4_$random_seed"
user_password_4="user_password_4_$random_seed"
user_credentials_4="state/user_credentials_4_$random_seed.pem"
email_4="email_4_$random_seed"

username_5="user_5_$random_seed"
full_name_5="name_5_$random_seed"
user_password_5="user_password_5_$random_seed"
user_credentials_5="state/user_credentials_5_$random_seed.pem"
email_5="email_5_$random_seed"

document_name="requirements_$random_seed"
file="../requirements.txt"

session_file="state/session_file1__$random_seed"
session_file_2="state/session_file2__$random_seed"
session_file_3="state/session_file3__$random_seed"
session_file_4="state/session_file4__$random_seed"
session_file_5="state/session_file5__$random_seed"

new_role="new_role_$random_seed"

###################### LOCAL COMMANDS ######################

## Create subject credentials
run_test success "1. Create subject credentials" ./rep_subject_credentials password1 state/new_data.pem
run_test success "1(1). Create subject credentials" ./rep_subject_credentials $user_password_2 $user_credentials_2
run_test success "1(2). Create subject credentials" ./rep_subject_credentials $user_password_3 $user_credentials_3
run_test success "1(3). Create subject credentials" ./rep_subject_credentials $user_password_4 $user_credentials_4
run_test success "1(4). Create subject credentials" ./rep_subject_credentials $user_password_5 $user_credentials_5
## Decrypt file
# TODO:......

####################### ANONYMOUS COMMANDS ######################

## Create Manager credentials
run_test success "2. Create Manager credentials" ./rep_subject_credentials $user_password $user_credentials

## Create an organization
run_test success "3. Create an organization" ./rep_create_org $organization_name $username $full_name $email $user_credentials
run_test failure "3(1). Create an organization" ./rep_create_org $organization_name $username $full_name $email $user_credentials
run_test success "3(2). Create an organization" ./rep_create_org $organization_name_2 $username $full_name $email $user_credentials # new organization
run_test success "3(3). Create an organization" ./rep_create_org $organization_name_3 $username $full_name $email $user_credentials # another new organization

## Lists all organizations
run_test success "5. List all organizations" ./rep_list_orgs

## Create a session
run_test success "6. Create a session" ./rep_create_session $organization_name $username $user_password $user_credentials $session_file
run_test failure "6(1). Create a session" ./rep_create_session ${organization_name}_not_found $username $user_password $user_credentials $session_file
run_test success "6(2). Create a session" ./rep_create_session $organization_name $username $user_password $user_credentials $session_file_2 # 2 sessions in the same org
run_test success "6(3). Create a session" ./rep_create_session $organization_name_2 $username $user_password $user_credentials $session_file_3 # a session with other org
run_test success "6(4). Create a session" ./rep_create_session $organization_name_3 $username $user_password $user_credentials $session_file_4 # a session with other new org

## Download a file given its handle
# run_test success "Download a file given it's handle" ./rep_get_file <file handle> [file]

# ###################### AUTHENTICATED COMMANDS ######################

## Assume session role
run_test success "7. Assume session role" ./rep_assume_role $session_file Managers
run_test failure "7(1). Assume session role" ./rep_assume_role $session_file \"Not Found\"
run_test success "7(2). Assume session role" ./rep_assume_role $session_file Managers # same role
run_test success "7(4). Assume session role" ./rep_assume_role $session_file_3 Managers # another org, is valid (since he has the role)

## Lists the current session roles
run_test success "8. Lists the current session roles" ./rep_list_roles $session_file # TODO: Como ficou a situação do argumento role?
run_test success "8(1). Lists the current session roles" ./rep_list_roles $session_file_2 # TODO: Como ficou a situação do argumento role?
run_test failure "8(2). Lists the current session roles" ./rep_list_roles ${session_file}_not_found # TODO: Como ficou a situação do argumento role?

## Lists the subjects' status
run_test success "9. Lists the organization's subjects' status" ./rep_list_subjects $session_file
run_test success "9(1). Lists the organization's subjects' status" ./rep_list_subjects $session_file $username
run_test failure "9(2). Lists the organization's subjects' status" ./rep_list_subjects $session_file ${username}_not_found
username_new="${username}_new"
run_test success "9(3). Adds a new subject" ./rep_add_subject $session_file $username_new ${full_name}_new ${email}_new $user_credentials
run_test success "9(4). Lists the organization's subjects' status" ./rep_list_subjects $session_file # show the status of all subjects
run_test_output success "$username_new: active" "9(5). Lists the organization's subjects' status" ./rep_list_subjects $session_file $username_new # show the status only of the new subject

# ## Lists only one subject's status
# run_test success "10. Lists only one subject's status" ./rep_list_subjects $session_file $username

# ## Lists the subjects of a role
# run_test success "11. Lists the subjects of a role" ./rep_list_role_subjects $session_file Managers
# run_test failure "11(1). Lists the subjects of a role" ./rep_list_role_subjects $session_file \"Not Found\"

# ## Lists the roles of a subject 
# run_test success "12. Lists the roles of a subject" ./rep_list_subject_roles $session_file $username
# run_test failure "12(1). Lists the roles of a subject" ./rep_list_subject_roles $session_file ${username}_not_found

# ## Lists the permissions of a role
# run_test success "13. Lists the permissions of a role" ./rep_list_role_permissions $session_file Managers
# run_test failure "13(1). Lists the permissions of a role" ./rep_list_role_permissions $session_file \"Not Found\"
# run_test success "13(2). Lists the permissions of a role" ./rep_list_role_permissions $session_file_3 Managers

# ## Add a document to the organization (this command needs authorization!!! - `DOC_NEW` permission)
run_test success "14. Add a document to the organization" ./rep_add_doc $session_file $document_name $file
run_test failure "14(1). Add a document to the organization" ./rep_add_doc $session_file $document_name $file
run_test success "14(2). Add a document to the organization" ./rep_add_doc $session_file ${document_name}_2 $file
run_test failure "14(3). Add a document to the organization" ./rep_add_doc $session_file_2 ${document_name}_3 $file # no authorization!! (didn't assume the role)
run_test success "14(4). Add a document to the organization" ./rep_add_doc $session_file_3 ${document_name}_2 $file # same name, different org -> different f

# ## Lists the roles that have a permission
# run_test success "15. Lists the roles that have a permission" ./rep_list_permission_roles $session_file SUBJECT_NEW
# run_test success "15(1). Lists the roles that have a permission" ./rep_list_permission_roles $session_file \"Not Found\" # TODO: ask Alfredo, should return [] or error?
# run_test success "15(2). Lists the roles that have a permission" ./rep_list_permission_roles $session_file DOC_READ
# #TODO: make tests with multiple roles per file!!!!

# ## Lists the documents of the organization
# run_test success "15(3). Lists the documents of the organization" ./rep_list_docs $session_file -s $username -d ot 06-12-2025 # organization 1
# run_test_output success "{}" "15(4). Lists the documents of the organization" ./rep_list_docs $session_file_4 -s $username -d ot 06-12-2025 # organization 3, should be empty because we didn't add any document to it

# TODO: check this better
#  check all possibilities of the command
#  also the creator!
#  and different organizations 

# # ###################### AUTHORIZED COMMANDS ######################

# Adds a new subject (fail)
run_test failure "16. Adds a new subject" ./rep_add_subject $session_file_2 $username_2 $full_name_2 $email_2 $user_credentials_2 # does not have a "SUBJECT_NEW" permission

# Adds a new subject and creates a session for the new user (success)
run_test success "16(1). Adds a new subject" ./rep_add_subject $session_file $username_2 $full_name_2 $email_2 $user_credentials_2
run_test success "16(2). Create a session for the new user" ./rep_create_session $organization_name $username_2 $user_password_2 $user_credentials_2 $session_file_5

## Suspends a subject
run_test failure "17. Suspends a subject" ./rep_suspend_subject $session_file_2 $username_2 # user does not have a SUBJECT_DOWN permission
run_test success "17(1). Suspends a subject" ./rep_suspend_subject $session_file $username_2

## Activate a subject
run_test failure "18. Activate a subject" ./rep_activate_subject $session_file_2 $username_2 # user does not have a SUBJECT_UP permission
run_test success "18(1). Activate a subject" ./rep_activate_subject $session_file $username_2

## Adds a new role
run_test failure "19. Adding a new role" ./rep_add_role $session_file_2 $new_role # user does not have a ROLE_NEW permission
run_test success "19(1). Adding a new role" ./rep_add_role $session_file $new_role

## Adds a permission to a role
run_test success "20. Adds a permission to a role" ./rep_add_permission $session_file $new_role SUBJECT_NEW

## Adds a subject to a role
run_test success "21. Adds a subject to a role" ./rep_add_permission $session_file $new_role $username_2
run_test success "21(1). Assume session role" ./rep_assume_role $session_file_5 $new_role # now has the role

## Suspends a role
run_test success "22. Suspends a role" ./rep_suspend_role $session_file $new_role

## Tries to add a subject with a suspended role
run_test failure "22(1). Adds a new subject with a suspended role" ./rep_add_subject $session_file_5 $username_3 $full_name_3 $email_3 $user_credentials_3

## Reactivates a role
run_test success "24. Reactivates a role" ./rep_reactivate_role $session_file $new_role

## Adds a new subject since the role is active
run_test success "24(1). Adds a new subject with a reactivated role" ./rep_add_subject $session_file_5 $username_3 $full_name_3 $email_3 $user_credentials_3

run_test failure "25. Removes a subject from a role" ./rep_remove_permission $session_file_2 $new_role $username_2
run_test success "25(1). Removes a subject from a role" ./rep_remove_permission $session_file $new_role $username_2
run_test failure "25(2). Adds a new subject after being removed from a role" ./rep_add_subject $session_file_5 $username_4 $full_name_4 $email_4 $user_credentials_4

run_test failure "26. Removes permission from a role" ./rep_remove_permission $session_file_2 $new_role SUBJECT_NEW # does not have a ROLE_MOD permission
run_test success "26(1). Removes permission from a role" ./rep_remove_permission $session_file $new_role SUBJECT_NEW
run_test failure "26(2). Adds a new subject" ./rep_add_subject $session_file_5 $username_5 $full_name_5 $email_5 $user_credentials_5 # does not have a SUBJECT_NEW permission

# Fetches the metadata of a document with a given name
run_test success "27. Fetches the metadata of a document with a given name" ./rep_get_doc_metadata $session_file $document_name

# Delete doc and observe that a soft delete is performed
run_test success "27(1). Deletes a document" ./rep_delete_doc $session_file $document_name

# Fetches the metadata of a document with a given name
run_test success "27(2). Fetches the metadata of a document with a given name" ./rep_get_doc_metadata $session_file $document_name

# Changes the ACL of a document by adding (+) or removing (-) a permission for a given role
run_test success "28. Changes the ACL of a document by adding a permission for a given role" ./rep_acl_doc $session_file $document_name \+ $new_role DOC_READ 
# TODO: test with (+)

# This commands requires a DOC_ACL permission.
run_test failure "28(2). Changes the ACL of a document by adding a permission for a given role" ./rep_acl_doc $session_file_2 $document_name \+ $new_role DOC_READ # does not have a DOC_ACL permission

# ###################### AUTHORIZED COMMANDS ######################

# List the subjects that are Managers of the organization with which I have currently a session.
run_test success "29. List the subjects that are Managers" ./rep_list_role_subjects $session_file Managers 

run_test failure "30. Suspend a subject" ./rep_suspend_subject $session_file $username # Should not work because Managers cannot be suspended

# Add Managers role
run_test failure "31(1). Add Managers role" ./rep_assume_role $session_file_5 Managers # fail because does not have the permission

# Suspend previous user
run_test success "31(2). Suspend a subject" ./rep_suspend_subject $session_file $username_2

# Add user2 to role Manager
run_test success "32. Add user2 to role Manager" ./rep_add_permission $session_file Managers $username_2
#run_test success "32(2). Add Managers role" ./rep_assume_role $session_file_5 Managers # now should work because user2 is a Manager

# Remove user from role Manager
run_test failure "33. Remove user from role Manager" ./rep_remove_permission $session_file Managers $username # should not work because Managers' role must have at least one user with a active status

# List the subjects that are Managers
run_test success "34. List the subjects that are Managers" ./rep_list_role_subjects $session_file Managers
run_test success "34(1). List the subjects" ./rep_list_subjects $session_file

# Reactivate user2
run_test success "35. Reactivate a subject" ./rep_activate_subject $session_file $username_2

# Suspend user (failure)
run_test failure "36. Suspend a subject" ./rep_suspend_subject $session_file $username # should not work because Managers cannot be suspended

# Remove user from role Manager
run_test success "37. Assume role Manager" ./rep_assume_role $session_file_5 Managers 
run_test success "37(1). Remove user from role Manager" ./rep_remove_permission $session_file_5 Managers $username

# List the subjects that are Managers
run_test success "38. List the subjects that are Managers" ./rep_list_role_subjects $session_file Managers
run_test success "38(1). List the subjects" ./rep_list_subjects $session_file

run_test success "39. Releases the session role [Managers]" ./rep_drop_role $session_file Managers

# List Metadata of a document
run_test failure "40. Get the metadata of a document" ./rep_get_doc_metadata $session_file $document_name # don't have DOC_READ
run_test success "40(1). Get the metadata of a document" ./rep_get_doc_metadata $session_file_5 $document_name

# Add user to new_role_seed
run_test failure "41. Add user to new_role" ./rep_add_permission $session_file $new_role $username_2 # (don't have ROLE_MOD)
run_test success "41(1). Add user to new_role" ./rep_add_permission $session_file_5 $new_role $username

# List Metadata of a document
run_test failure "42. Get the metadata of a document" ./rep_get_doc_metadata $session_file $document_name
run_test success "42(1). Assume role new_role" ./rep_assume_role $session_file $new_role
run_test success "42(2). Get the metadata of a document" ./rep_get_doc_metadata $session_file $document_name

# Remove DOC_ACL permission from Managers in a document
run_test failure "43. Remove DOC_ACL permission from Managers in a document" ./rep_acl_doc $session_file $document_name \- Managers DOC_ACL # don't have (DOC_ACL)
run_test failure "43(1). Remove DOC_ACL permission from Managers in a document" ./rep_acl_doc $session_file_5 $document_name \- Managers DOC_ACL  # at least one DOC_ACL per document

# Add DOC_ACL permission to new_role in a document
run_test success "44. Add DOC_ACL permission to new_role in a document" ./rep_acl_doc $session_file_5 $document_name \+ $new_role DOC_ACL
run_test success "44(1). Get the metadata of a document" ./rep_get_doc_metadata $session_file_5 $document_name

# Remove DOC_ACL permission from Managers in a document
run_test success "45. Remove DOC_ACL permission from Managers in a document" ./rep_acl_doc $session_file_5 $document_name \- Managers DOC_ACL
run_test fail "45(1). Remove DOC_ACL permission from Other role in a document" ./rep_acl_doc $session_file $document_name \- $new_role DOC_ACL


