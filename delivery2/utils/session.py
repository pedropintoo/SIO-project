import json
from utils import symmetric
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import requests


def session_info_from_file(session_file):
    """
    Reads session details from a file.
    Args:
        session_file (str): The path to the session file.
    Returns:
        dict: The session details.
    """
    session = None
    with open(session_file, 'r') as f:
        session = json.load(f)
    return session

def encapsulate_session_data(plaintext, session_id, derived_key_hex, msg_id):
    """
    Encrypts and processes data to be sent to the client, with respective session details (with encryption & authentication).
    Args:
        plaintext (dict): The data to be encrypted.
        session_id (int): The session ID.
        derived_key (str): The derived key.
        msg_id (int): The message ID.
    Returns:
        dict: The encrypted data to be sent to the client.
    """

    # Authenticated but not encrypted data
    associated_data = {'msg_id': msg_id, 'session_id': session_id}
    associated_data_bytes = json.dumps(associated_data).encode("utf-8")    
    associated_data_string = associated_data_bytes.decode("utf-8")

    # Encrypt data
    plaintext_bytes = json.dumps(plaintext).encode("utf-8")
    derived_key_bytes = bytes.fromhex(derived_key_hex)
    
    nonce, ciphertext = symmetric.encrypt(derived_key_bytes, plaintext_bytes, associated_data_bytes)

    encrypted_data = {
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex()
    }

    return {'associated_data': associated_data, 'encrypted_data': encrypted_data}

def decapsulate_session_data(data, sessions):
    """
    Decrypts and processes data received from the client, with respective session details (with decryption & authentication).
    Args:
        request.get_json() (flask.Request): The request object containing the encrypted data.
        sessions (dict): The dictionary containing session details.
    Returns:
        dict: The decrypted data received from the client.
    """
        
    # Associated data (authenticated but not encrypted)
    associated_data = data.get('associated_data')
    session_id = associated_data.get('session_id')
    msg_id = associated_data.get('msg_id')
    
    # Encrypted data
    encrypted_data = data.get('encrypted_data')
    nonce_hex = encrypted_data.get('nonce')
    ciphertext_hex = encrypted_data.get('ciphertext')
    
    # Get session details
    session = sessions.get(session_id)
    if session is None:
        raise Exception(f'Session {session_id} not found')
    
    # Check for replays
    if msg_id <= session['msg_id']:
        raise Exception(f'Replay attack detected for session {session_id}')
    
    # Get session details
    organization = session['organization']
    username = session['username']
    derived_key_hex = session['derived_key']

    # Validate integrity & decrypt data
    try: 
        plaintext_bytes = symmetric.decrypt(bytes.fromhex(derived_key_hex), bytes.fromhex(nonce_hex), bytes.fromhex(ciphertext_hex), json.dumps(associated_data).encode("utf-8"))
    except InvalidTag:
        raise Exception(f'Error decrypting data for session {session_id} (InvalidTag)') 
    
    except Exception as e:
        raise Exception(f'Error decrypting data for session {session_id} ({e})')

    plaintext = json.loads(plaintext_bytes.decode("utf-8"))
    
    return plaintext, organization, username, msg_id, session_id, derived_key_hex

def send_session_data(logger, server_address, command, endpoint, session_file, plaintext):

    session = session_info_from_file(session_file)

    msg_id = session['msg_id'] + 1 # prevent replay attacks
    session_id = session['session_id']
    derived_key_hex = session['derived_key']
    organization = session['organization']
    usernameSession = session['username']

    # Update session file
    with open(session_file, 'w') as f:
        session['msg_id'] = msg_id
        json.dump(session, f, indent=4)
        
    # Add integrity and confidentiality to data
    data = encapsulate_session_data(
        plaintext, 
        session_id,
        derived_key_hex,
        msg_id
    )
        
    # Send data to server
    if command == "get":
        request_func = requests.get
    elif command == "post":
        request_func = requests.post
    elif command == "put":
        request_func = requests.put
    elif command == "delete":
        request_func = requests.delete    

    result = request_func(f'{server_address}{endpoint}', json={'associated_data': data["associated_data"], 'encrypted_data': data["encrypted_data"]})

    sessions = {session_id: {"msg_id": msg_id, "organization": organization, "derived_key": derived_key_hex, "username": usernameSession}}
    plaintext, _, _, msg_id, _, _ = decapsulate_session_data(json.loads(result.text), sessions)

    if msg_id <= session['msg_id']:
        raise Exception(f'Replay attack detected for session {session_id}')

    # Update session file
    with open(session_file, 'w') as f:
        session['msg_id'] = msg_id
        json.dump(session, f, indent=4)
        
    if result.status_code != 200:
        raise Exception(f'[{result.status_code}] Failed to execute default command: {endpoint}. Response: {plaintext}')

    return plaintext

def check_user_permission_in_session(logger, permission, session, organization_db):
    
    if 'roles' not in session:
        logger.error('Roles not found in session')
        return False
    
    roles = session['roles']
    if roles is None:
        logger.error('Roles not found in session')
        return False

    logger.debug(f'Checking permission {permission} for roles {roles}')
    return organization_db.check_role_permission(session['organization'], roles, permission)
    
def get_document_handle(organization_name, document_name):
    """ Returns the document handle, i.e. a digest, for the given organization and document name. """  
    concatenated = (organization_name + document_name).encode('utf-8')

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(concatenated)
    file_handle_hex = digest.finalize().hex()
    
    return file_handle_hex
