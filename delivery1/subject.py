import sys
import logging
from client.state import load_state, parse_env, parse_args, save
from client.parser import CommandsParser

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO) # change to DEBUG for verbose logging

state = load_state(logger)
state = parse_env(logger, state)
args, state = parse_args(logger, state)

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
result = CommandsParser.execute(logger, state, args)

## Save Persistent State
save(logger, state)

# --------------------------------------------------------------------

sys.exit(result)
