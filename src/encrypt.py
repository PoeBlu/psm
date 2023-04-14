import base64
import boto3
import logging
import os
import uuid

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    
    logger.info('Incoming event!')

    try:

        secret = get_secret(event)

        if secret is None:

            logger.info('Err: No secret supplied with POST method.')

            return {
                'statusCode': 400,
                'body': 'Err: No secret supplied with POST method.',
                'headers': {'Content-Type': 'text/plain'},
            }
        cipher = encrypt(secret)

        logger.info(cipher)

        return {
            'statusCode': 200,
            'body': cipher,
            'headers': {'Content-Type': 'text/plain'},
        }
    except:

        return {
            'statusCode': 500,
            'body': 'Err: Internal server error.',
            'headers': {'Content-Type': 'text/plain'},
        }

def get_secret(event):

    method = event['httpMethod']
    logger.info(f'Method: {method}')

    if method == 'POST':
        secret = event['body']
        logger.info('Secret parsed!')

    else:
        secret = str(uuid.uuid4())
        logger.info('Secret generated!')

    return secret

def encrypt(secret):

    key = os.environ['KMS_KEY_ALIAS']
    logger.info(f'KMS Key: {key}')

    kms = get_client()
    kms_response = kms.encrypt(KeyId=key, Plaintext=secret.encode())
    logger.info(f'KMS Response:\n{kms_response}')

    blob = base64.b64encode(kms_response['CiphertextBlob'])
    logger.info(f'Blob: {blob}')

    return f'cipher:{blob.decode()}'

def get_client():
    
    region = os.environ['REGION']
    return boto3.client('kms', region_name=region)