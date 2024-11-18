import json
from server.utils import symmetric
import base64
import requests

def default_command(logger, server_address, url, plaintext, session_file):
    """
    Executes a default command by encrypting the provided plaintext and sending it to the specified server.
    Args:
        server_address (str): The address of the server to send the request to.
        url (str): The URL endpoint on the server.
        plaintext (dict): The plaintext data to be encrypted and sent.
        session_file (str): The path to the session file containing session details.
    Returns:
        requests.Response: The response object from the server after sending the encrypted data.
    """

    logger.debug(f'Executing default command: {url}')
    
    session_id = None
    derived_key = None
    client_username = None
    msg_id = None

    with open(session_file, 'r') as f:
        session = json.load(f)
        session_id = session['session_id']
        derived_key = session['derived_key']
        client_username = session['username']
        msg_id = session['msg_id'] + 1
    
    # Update session file
    with open(session_file, 'w') as f:
        session['msg_id'] = msg_id
        f.write(json.dumps(session, indent=4)) 

    associated_data = {'session_id': session_id, 'msg_id': msg_id}
    associated_data_bytes = json.dumps(associated_data).encode()    
    logger.debug(f'Associated data: {associated_data}')

    plaintext_bytes = json.dumps(plaintext).encode()

    derived_key_bytes = base64.b64decode(derived_key)
    
    # Encrypt data
    nonce, ciphertext = symmetric.encrypt(derived_key_bytes, plaintext_bytes, associated_data_bytes)
    logger.debug(f'Nonce: {base64.b64encode(nonce).decode()}')
    logger.debug(f'Ciphertext: {base64.b64encode(ciphertext).decode()}')
    logger.debug(f"Derived key: {derived_key_bytes}")
    logger.debug(f"Plaintext: {plaintext_bytes}")
    logger.debug(f"Associated data: {associated_data_bytes}")
    
    
    encrypted_data = {
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }

    result = requests.get(f'{server_address}{url}', json={'associated_data': associated_data, 'encrypted_data': encrypted_data})
    
    if result.status_code != 200:
        logger.error(f'Failed to execute default command: {url}')
        logger.error(f'Server response: {result.text}')
        return None
    
    return result
