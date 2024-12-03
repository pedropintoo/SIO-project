#!/bin/bash

## !WARNING! ## 

# This script only works if the server is running on the same machine and on the default port (5000)
# docker compose up in `delivery1` folder to start the server

## !WARNING! ##


cd ..
python3 subject.py -k server/rep_pub.pem -r "http://127.0.0.1:5000"
cd commands


# Session 1
./rep_create_org hackers pmap Pedro pmap@ua.pt state/credentials.pem

./rep_create_session hackers pmap jorge state/credentials.pem state/session_file1


# Session 2
./rep_create_org guests pmap Pedro pmap@ua.pt state/credentials.pem

./rep_create_session guests pmap jorge state/credentials.pem state/session_file2

./rep_list_orgs




./rep_list_subjects state/session_file1

./rep_list_subjects state/session_file1 pmap



./rep_add_subject state/session_file1 jj jorge jj@ua.pt state/credentials2.pem

./rep_suspend_subject state/session_file1 jj
./rep_list_subjects state/session_file1

./rep_activate_subject state/session_file1 jj
./rep_list_subjects state/session_file1



./rep_add_doc state/session_file1 requirements ../requirements.txt

./rep_get_doc_metadata state/session_file1 requirements



./rep_list_docs state/session_file1


./rep_get_doc_file state/session_file1 requirements


./rep_delete_doc state/session_file1 requirements

./rep_list_docs state/session_file1
