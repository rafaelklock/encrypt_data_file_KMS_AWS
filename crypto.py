import base64
import logging
import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
import os


def get_session_aws():
    aws_region = os.environ.get('SYSTEM_AWS_REGION_NAME', "")
    local_aws_profile = os.environ.get('LOCAL_AWS_PROFILE', "")

    if local_aws_profile != "":
        return boto3.Session(region_name=aws_region, profile_name=local_aws_profile).client('kms')
    else:
        return boto3.Session(region_name=aws_region).client('kms')


def retrieve_cmk(desc):
    """
    Recupera a CMK na AWS, com base na descricao
    """
    kms_client = get_session_aws()

    try:
        response = kms_client.list_keys()
    except ClientError as e:
        logging.error(e)
        return None, None

    done = False
    while not done:
        for cmk in response['Keys']:
            try:
                key_info = kms_client.describe_key(KeyId=cmk['KeyArn'])
            except ClientError as e:
                logging.error(e)
                return None, None

            if key_info['KeyMetadata']['Description'] == desc:
                return cmk['KeyId'], cmk['KeyArn']

        if not response['Truncated']:
            logging.debug('A CMK with the specified description was not found')
            done = True
        else:
            try:
                response = kms_client.list_keys(Marker=response['NextMarker'])
            except ClientError as e:
                logging.error(e)
                return None, None

    return None, None


def create_cmk(desc='DataTeam Master Key'):
    # Create CMK
    kms_client = get_session_aws()
    try:
        response = kms_client.create_key(Description=desc)
    except ClientError as e:
        logging.error(e)
        return None, None

    return response['KeyMetadata']['KeyId'], response['KeyMetadata']['Arn']


def create_data_key(cmk_id, key_spec='AES_256'):
    kms_client = get_session_aws()
    try:
        response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec)
    except ClientError as e:
        logging.error(e)
        return None, None

    return response['CiphertextBlob'], base64.b64encode(response['Plaintext'])


def decrypt_data_key(data_key_encrypted):
    kms_client = get_session_aws()
    try:
        response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)
    except ClientError as e:
        logging.error(e)
        return None

    return base64.b64encode((response['Plaintext']))


def encrypt_data(data, cmk_id):
    NUM_BYTES_FOR_LEN = 4
    data_key_encrypted, data_key_plaintext = create_data_key(cmk_id)
    if data_key_encrypted is None:
        return False
    logging.info('Criada nova KMS data key')

    f = Fernet(data_key_plaintext)
    contents_encrypted = f.encrypt(data)
    logging.info('Envelopando os dados')
    data_encrypted = len(data_key_encrypted).to_bytes(NUM_BYTES_FOR_LEN, byteorder='big') + data_key_encrypted + contents_encrypted
    return data_encrypted


def decrypt_data(data):
    NUM_BYTES_FOR_LEN = 4
    data_key_encrypted_len = int.from_bytes(data[:NUM_BYTES_FOR_LEN], byteorder='big') + NUM_BYTES_FOR_LEN
    data_key_encrypted = data[NUM_BYTES_FOR_LEN:data_key_encrypted_len]
    data_key_plaintext = decrypt_data_key(data_key_encrypted)

    if data_key_plaintext is None:
        logging.error("Cannot decrypt the data key")
        return False

    f = Fernet(data_key_plaintext)
    data_contents_decrypted = f.decrypt(data[data_key_encrypted_len:])
    return data_contents_decrypted
