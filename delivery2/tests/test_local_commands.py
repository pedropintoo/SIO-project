import sys
import logging
from client.state import load_state, parse_env, parse_args, save
from client.commands import Local

import pytest

@pytest.fixture
def local():
    logging.basicConfig(format='%(levelname)s\t- %(message)s')
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG) # change to DEBUG for verbose logging
    state = load_state(logger)
    logger.debug('REP_PUB_KEY: ' + state['REP_PUB_KEY'][27:40] + '...')
    logger.debug('REP_ADDRESS: ' + state['REP_ADDRESS'])
    return Local(logger, state)

def test_rep_subject_credentials(local):
    local.rep_subject_credentials(password="rep_subject_credentials", credentials_file="tests/raw_files/new_data.pem")
        
    with open("tests/raw_files/new_data.pem", "r") as f:
        new_data = f.read()
    
    with open("tests/raw_files/rep_subject_credentials.pem", "r") as f:
        rep_subject_credentials = f.read()
        
    assert new_data == rep_subject_credentials

# TODO: ...
# def test_rep_decrypt_file(local):  
#     local.rep_decrypt_file(encrypted_file="tests/raw_files/encrypted_data.enc", encryption_metadata="tests/raw_files/encryption_metadata.json")

#     with open("tests/raw_files/decrypted_data.txt", "r") as f:
#         decrypted_data = f.read()

#     with open("tests/raw_files/original_data.txt", "r") as f:
#         original_data = f.read()

#     assert decrypted_data == original_data
    
    
    
    