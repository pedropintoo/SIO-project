import sys
import logging
from client.state import load_state, parse_env, parse_args, save
from client.commands import Auth, Organization

import pytest
import random
import string

@pytest.fixture
def random_seed():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))

@pytest.fixture
def auth():
    logging.basicConfig(format='%(levelname)s\t- %(message)s')
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG) # change to DEBUG for verbose logging
    state = load_state(logger)
    logger.debug('REP_PUB_KEY: ' + state['REP_PUB_KEY'][27:40] + '...')
    logger.debug('REP_ADDRESS: ' + state['REP_ADDRESS'])
    return Auth(logger, state)

@pytest.fixture
def organization():
    logging.basicConfig(format='%(levelname)s\t- %(message)s')
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG) # change to DEBUG for verbose logging
    state = load_state(logger)
    logger.debug('REP_PUB_KEY: ' + state['REP_PUB_KEY'][27:40] + '...')
    logger.debug('REP_ADDRESS: ' + state['REP_ADDRESS'])
    return Organization(logger, state)

def test_rep_create_org(auth, random_seed):

    org_name = 'org_' + random_seed
    user_name = 'user_' + random_seed
    name = 'name_' + random_seed
    email = 'email_' + random_seed
    pub_key = 'tests/raw_files/rep_pub.pem'

    try:
        result = auth.rep_create_org(org_name, user_name, name, email, pub_key)
    except Exception as e:
        assert False, e
        
    try:
        # error: organization already exists
        result = auth.rep_create_org(org_name, user_name, name, email, pub_key)        
        assert False, 'Organization already exists'
    except Exception as e:
        pass
        
    try:
        # error: file not found
        pub_key = 'tests/raw_files/rep_pub_not_found.pem'
        result = auth.rep_create_org(org_name, user_name, name, email, pub_key)
        assert False, 'File not found'
    except Exception as e:
        pass
        
    assert True

def test_rep_list_orgs(organization):
    try:
        result = organization.rep_list_orgs()
    except Exception as e:
        assert False, e
    assert True
    
def test_rep_create_session(auth, random_seed):
    org_name = 'org_' + random_seed
    user_name = 'user_' + random_seed
    password = 'password_' + random_seed
    credentials_file = 'tests/raw_files/credentials.pem'
    session_file = 'tests/raw_files/session' + '.json'
    
    # create organization
    try:
        result = auth.rep_create_org(org_name, user_name, 'name', 'email', 'tests/raw_files/rep_pub.pem')
    except Exception as e:
        assert False, e
    
    try:
        auth.rep_create_session(org_name, user_name, password, credentials_file, session_file)
    except Exception as e:
        assert False, e
        
    try:
        # error: organization not found
        org_name = 'org_not_found'
        auth.rep_create_session(org_name, user_name, password, credentials_file, session_file)
        assert False, 'Organization not found'
    except Exception as e:
        pass
        
    try:
        # error: file not found
        org_name = 'org_' + random_seed
        credentials_file = 'tests/raw_files/credentials_not_found.pem'
        auth.rep_create_session(org_name, user_name, password, credentials_file, session_file)
        assert False, 'File not found'
    except Exception as e:
        pass
        
    
    assert True

# def test_bash_script():
#     result = subprocess.run(
#         ['./your_script.sh'],
#         capture_output=True,
#         text=True
#     )
#     assert result.returncode == 0
#     assert 'Expected output' in result.stdout
    

# def compare_decl_lists(l1,l2):
#     l1_tuples = [str(d) for d in l1]
#     l2_tuples = [str(d) for d in l2]
#     return len(l1_tuples)==len(l2_tuples) and set(l1_tuples)==set(l2_tuples)

# def test_exercicio10(sn_net):
#     assert sn_net.predecessor_path('vertebrado','socrates') == ['vertebrado', 'mamifero', 'homem', 'socrates']

# def test_exercicio11(sn_net):
#     assert compare_decl_lists(sn_net.query('socrates','altura'),[
# Declaration('descartes',Association('mamifero','altura',1.2)), \
# Declaration('descartes',Association('homem','altura',1.75)), \
# Declaration('simao',Association('homem','altura',1.85)), \
# Declaration('darwin',Association('homem','altura',1.75))] )

#     assert compare_decl_lists(sn_net.query('platao'), [
# Declaration('darwin',Association('mamifero','mamar','sim')), \
# Declaration('descartes',Association('mamifero','altura',1.2)), \
# Declaration('darwin',Association('homem','gosta','carne')), \
# Declaration('descartes',Association('homem','altura',1.75)), \
# Declaration('simao',Association('homem','altura',1.85)), \
# Declaration('darwin',Association('homem','altura',1.75)), \
# Declaration('descartes',Association('platao','professor','filosofia')), \
# Declaration('simao',Association('platao','professor','filosofia')), \
# Declaration('darwin',Association('platao','peso',75))] )

#     assert compare_decl_lists(sn_net.query2('platao'), [
# Declaration('darwin',Association('mamifero','mamar','sim')), \
# Declaration('descartes',Association('mamifero','altura',1.2)), \
# Declaration('darwin',Association('homem','gosta','carne')), \
# Declaration('descartes',Association('homem','altura',1.75)), \
# Declaration('simao',Association('homem','altura',1.85)), \
# Declaration('darwin',Association('homem','altura',1.75)), \
# Declaration('descartes',Association('platao','professor','filosofia')), \
# Declaration('simao',Association('platao','professor','filosofia')), \
# Declaration('darwin',Association('platao','peso',75)), \
# Declaration('descartes',Member('platao','homem'))] )

# def test_exercicio12(sn_net):
#     assert compare_decl_lists(sn_net.query_cancel('socrates','altura'), [
# Declaration('descartes',Association('homem','altura',1.75)), \
# Declaration('simao',Association('homem','altura',1.85)), \
# Declaration('darwin',Association('homem','altura',1.75))] )

# def test_exercicio13(sn_net):
#     assert compare_decl_lists(sn_net.query_down('vertebrado', 'altura'), [
# Declaration('descartes',Association('mamifero','altura',1.2)), \
# Declaration('descartes',Association('homem','altura',1.75)), \
# Declaration('simao',Association('homem','altura',1.85)), \
# Declaration('darwin',Association('homem','altura',1.75))] )

#     assert compare_decl_lists(sn_net.query_down('mamifero', 'altura'), [
# Declaration('descartes',Association('homem','altura',1.75)), \
# Declaration('simao',Association('homem','altura',1.85)), \
# Declaration('darwin',Association('homem','altura',1.75))] )

#     assert compare_decl_lists(sn_net.query_down('homem', 'altura'), [])


