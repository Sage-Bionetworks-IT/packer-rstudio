#!/usr/bin/env python3

import jwt
import requests
import base64
import json
import boto3
import time
import functools
import os

from mod_python import apache

region = json.loads(requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document').text)['region']
ssm_parameter_name_env_var = 'SYNAPSE_TOKEN_AWS_SSM_PARAMETER_NAME'
kms_alias_env_var = 'KMS_KEY_ALIAS'

def headerparserhandler(req):
  jwt_str = req.headers_in['x-amzn-oidc-data'] #proxy.conf ensures this header exists

  try:
    payload = jwt_payload(jwt_str)

    if payload['userid'] == approved_user() and payload['exp'] > time.time():
      store_to_ssm(req.headers_in['x-amzn-oidc-accesstoken'])
      return apache.OK
    else:
      return apache.HTTP_UNAUTHORIZED #the userid claim does not match the userid tag
  except Exception:
    # if the JWT playload is invalid
    return apache.HTTP_UNAUTHORIZED

def approved_user():
  instance_id = requests.get('http://169.254.169.254/latest/meta-data/instance-id').text

  ec2 = boto3.resource('ec2',region)
  vm = ec2.Instance(instance_id)

  #TODO handle exception on multiple tags in this list
  for tags in vm.tags:
    if tags["Key"] == 'Protected/AccessApprovedCaller':
      approved_caller = tags["Value"]

  return approved_caller.split(':')[1] #return userid portion of tag

# taking advantage of lru cache to avoid re-putting the same access token to
# SSM Parameter Store.
# According to functools source code, arguments (i.e. the access token) are hashed,
# not stored as-is in memory
@functools.lru_cache(maxsize=1)
def store_to_ssm(access_token):
  parameter_name = os.environ.get(ssm_parameter_name_env_var)
  kms_key_alias = os.environ.get(kms_alias_env_var)
  if not (parameter_name):
    # just exit early if the parameter name to store in SSM is not found
    return

  ssm_client = boto3.client('ssm', region)
  kms_client = boto3.client('kms', region)
  key_id = kms_client.describe_key(KeyId=kms_key_alias)['KeyMetadata']['KeyId']

  ssm_client.put_parameter(
    Name=parameter_name,
    Type='SecureString',
    Value=access_token,
    KeyId=key_id,
    Overwrite=True
  )

def jwt_payload(encoded_jwt):

  # The x-amzn-oid-data header is a base64-encoded JWT signed by the ALB
  # validating the signature of the JWT means the payload is authentic
  # per http://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
  # Step 1: Get the key id from JWT headers (the kid field)
  #encoded_jwt = headers.dict['x-amzn-oidc-data']
  jwt_headers = encoded_jwt.split('.')[0]

  decoded_jwt_headers = base64.b64decode(jwt_headers).decode("utf-8")
  decoded_json = json.loads(decoded_jwt_headers)
  kid = decoded_json['kid']

  # Step 2: Get the public key from regional endpoint
  pub_key = get_aws_elb_public_key(region, kid)

  # Step 3: Get the payload
  return jwt.decode(encoded_jwt, pub_key, algorithms=['ES256'])

@functools.lru_cache()
def get_aws_elb_public_key(region, key_id):
  url = f'https://public-keys.auth.elb.{region}.amazonaws.com/{key_id}'
  return requests.get(url).text
