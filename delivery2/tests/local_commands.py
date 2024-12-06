import sys
import logging
from client.state import load_state, parse_env, parse_args, save
from client.commands import Local

import pytest

@pytest.fixture
def cp():
    logging.basicConfig(format='%(levelname)s\t- %(message)s')
    logger = logging.getLogger()
    logger.setLevel(logging.INFO) # change to DEBUG for verbose logging

    state = load_state(logger)
    state = parse_env(logger, state)
    _, state = parse_args(logger, state)

    if 'REP_ADDRESS' not in state:
        logger.error("Must define Repository Address")
        sys.exit(-1)

    if 'REP_PUB_KEY' not in state:
        logger.error("Must set the Repository Public Key")
        sys.exit(-1)

    logger.debug('REP_PUB_KEY: ' + state['REP_PUB_KEY'][27:40] + '...')
    logger.debug('REP_ADDRESS: ' + state['REP_ADDRESS'])
    # --------------------------------------------------------------------

    ## Execute Command
    return Local(logger, state)

def rep_subject_credentials(cp):
    cp.rep_subject_credentials("rep_subject_credentials", "tests/raw_files/new_data.pem")
    
    with open("tests/raw_files/new_data.pem", "r") as f:
        new_data = f.read()
    
    with open("tests/raw_files/rep_subject_credentials.pem", "r") as f:
        rep_subject_credentials = f.read()
        
    assert new_data == rep_subject_credentials

# def test_exercicio15():
#     assert all([k in ['sc', 'pt', 'cp', 'fr', 'pa', 'cnl'] for k in sof2018h.bn.dependencies.keys()])

#     assert len(sof2018h.bn.dependencies['sc']) == 1
#     assert len(sof2018h.bn.dependencies['pt']) == 1
#     assert len(sof2018h.bn.dependencies['cp']) == 4
#     assert len(sof2018h.bn.dependencies['fr']) == 4
#     assert len(sof2018h.bn.dependencies['pa']) == 2
#     assert len(sof2018h.bn.dependencies['cnl']) == 2

#     assert sof2018h.bn.jointProb([(v,True) for v in sof2018h.bn.dependencies]) == 0.0001215
    
#     assert sof2018h.bn.jointProb([('sc', True)]) == round(sof2018h.bn.individualProb('sc', True),5)
#     assert sof2018h.bn.jointProb([('pt', False)]) == round(sof2018h.bn.individualProb('pt', False),5)

#     assert round(sof2018h.bn.individualProb('pa', True),5) == 0.0163

