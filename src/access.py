#!/usr/bin/env python

import jwt
import requests
import base64
import json
import boto3

from mod_python import apache

region = 'us-east-1'

def headerparserhandler(req):

  jwt = req.headers_in['x-amzn-oidc-data'] #proxy.conf ensures this header exists

  if session_user(jwt) == approved_user():
    return apache.OK
  else:
    return apache.HTTP_UNAUTHORIZED #the userid claim does not match the userid tag

def approved_user():
  meta = requests.get('http://169.254.169.254/latest/meta-data/instance-id')
  instance_id = meta.text

  ec2 = boto3.resource('ec2',region)
  vm = ec2.Instance(instance_id)

  #TODO handle exception on multiple tags in this list
  for tags in vm.tags:
    if tags["Key"] == 'Protected/AccessApprovedCaller':
      approved_caller = tags["Value"]

  return approved_caller.split(':')[1] #return userid portion of tag

def session_user(encoded_jwt):

  # The x-amzn-oid-data header is a base64-encoded JWT signed by the ALB
  # validating the signature of the JWT means the payload is authentic
  # per http://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
  # Step 1: Get the key id from JWT headers (the kid field)
  #encoded_jwt = headers.dict['x-amzn-oidc-data']
  jwt_headers = encoded_jwt.split('.')[0]

  decoded_jwt_headers = base64.b64decode(jwt_headers)
  decoded_jwt_headers = decoded_jwt_headers.decode("utf-8")
  decoded_json = json.loads(decoded_jwt_headers)
  kid = decoded_json['kid']

  # Step 2: Get the public key from regional endpoint
  url = 'https://public-keys.auth.elb.' + region + '.amazonaws.com/' + kid
  req = requests.get(url)
  pub_key = req.text

  # Step 3: Get the payload
  payload = jwt.decode(encoded_jwt, pub_key, algorithms=['ES256'])
  #TODO handle validation errors, this call validates the signature

  return payload['userid']
