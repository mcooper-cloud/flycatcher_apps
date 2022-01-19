
###############################################################################
###############################################################################
##
##  the purpose of this Lambda function is to 
##  manage events from an Auth0 log stream
##
###############################################################################
###############################################################################

import json
import base64
import os
import uuid
import requests
import urllib.parse
import datetime
import time
import multiprocessing

import jwt
from jwt import PyJWKClient

import logging

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='/var/log/auth0.log',
                    filemode='w')

'''
import boto3 
import botocore
from botocore.exceptions import ClientError
'''

class Auth0(object):

    def __init__( self, 
                  client_id=None, 
                  client_secret=None,
                  auth0_domain=None,
                  audience=None,
                  grant_type=None ):

        self.client_id = client_id
        self.client_secret = client_secret
        self.auth0_domain = auth0_domain

        base_url = 'https://{}'.format(self.auth0_domain)

        self.mgmt_endpoint = '{}/api/v2'.format(base_url)
        self.token_endpoint = '{}/oauth/token'.format(base_url)

        if audience is None:
            self.audience = '{}/'.format(self.mgmt_endpoint)
        else:
            self.audience = audience

        if grant_type is None:
            self.grant_type = 'client_credentials'
        else:
            self.grant_type = grant_type

        self.get_token()

        p = multiprocessing.Process(target=self.token_watcher)


    ##########################################################################
    ##########################################################################
    ##
    ## get token
    ##
    ##########################################################################
    ##########################################################################


    def get_token(self):

        try:
            token_data = {
                'client_id' : self.client_id,
                'client_secret' : self.client_secret,
                'audience' : self.audience,
                'grant_type' : self.grant_type
            }

            logging.debug('[+] Getting access token from : {}'.format(self.token_endpoint))

            token_response = requests.post(self.token_endpoint, json=token_data)

            self.access_token = token_response.json()['access_token']

            token_data = json.loads(self.decode_token())

            if 'exp' in token_data:
                exp = datetime.datetime.utcfromtimestamp(token_data['exp'])
                logging.debug('[+] Token exp claim: {}'.format(token_data['exp']))

            now = datetime.datetime.utcnow()
            logging.debug('[+] UTC now: {}'.format(now))
            logging.debug('[+] Time delta to token expire: {}'.format((exp-now).seconds))


            ##
            ## TODO: multiply expiration delta by random percentage
            ##       between 0.7 (~16hrs) and 0.9 (~21hrs) to prevent
            ##       a potential instantaineous mass token refresh 
            ##       bomb at scale
            ##
            self.token_refresh_interval = ((exp-now).seconds)*0.8
            logging.debug('[+] Token refresh interval: {}'.format(self.token_refresh_interval))

            return self.access_token

        except Exception as e:
            logging.debug('[-] Error getting token: {}'.format(e))


    ##########################################################################
    ##########################################################################
    ##
    ## decode token
    ##
    ##########################################################################
    ##########################################################################


    def decode_token(self, token=None):

        logging.debug('[+] Decoding access token')

        if token is None:
            t = self.access_token
        else:
            t = token

        token_data = JWT( token=t, 
                          audience=self.audience, 
                          auth0_domain=self.auth0_domain )

        return json.dumps(token_data.decode())


    ##########################################################################
    ##########################################################################
    ##
    ## token watcher
    ##
    ##########################################################################
    ##########################################################################


    def token_watcher(self):
        while True:
            logging.debug('[+] Current Time {}'.format(datetime.datetime.now()))
            logging.debug('[+] Sleeping for {}'.format(self.token_refresh_interval))
            time.sleep(self.token_refresh_interval)
            self.get_token()



##############################################################################
##############################################################################
##
##
##
##############################################################################
##############################################################################


class JWT(object):

    def __init__( self, 
                  token=None,
                  audience=None,
                  auth0_domain=None ):

        self.token = token
        self.audience = audience
        self.auth0_domain = auth0_domain

        logging.debug('[+] Initializing JWT Object: {}'.format(self.token))

        self.token_data = self.decode()


    def decode(self):

        jwks_url = 'https://{}/.well-known/jwks.json'.format(self.auth0_domain)
        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(self.token)

        data = jwt.decode(
            self.token,
            signing_key.key,
            algorithms=['RS256'],
            audience=self.audience,
            options={'verify_exp': False}
        )

        return data


    ##########################################################################
    ##########################################################################
    ##
    ## get custom claims
    ##
    ##########################################################################
    ##########################################################################


    def get_custom_claims(self, claims_list=None):

        try:

            if claims_list is not None:

                custom_claims = {}
                for c in claims_list:
                    if c in self.token_data:

                        logging.debug('[+] Found custom claim value {} : {}'.format(c, self.token_data[c]))
                        custom_claims[c] = self.token_data[c]

                return custom_claims
            else:
                return None

        except Exception as e:
            logging.debug('[-] Error retrieving custom claims: {}'.format(e))
            return None


    ##########################################################################
    ##########################################################################
    ##
    ## get permissions
    ##
    ##########################################################################
    ##########################################################################


    def get_permissions(self):
        try:
            permissions = []
            if 'permissions' in self.token_data:

                for p in self.token_data['permissions']:

                    logging.debug('[+] Found permission value {}'.format(p))
                    permissions.append(p)

                return permissions
            else:
                return None

        except Exception as e:
            logging.debug('[-] Error retrieving permissions: {}'.format(e))
            return None


    ##########################################################################
    ##########################################################################
    ##
    ## get org ID
    ##
    ##########################################################################
    ##########################################################################


    def get_org_id(self):

        try:
            if 'org_id' in self.token_data:
                org_id = self.token_data['org_id']
                return org_id
            else:
                return None

        except Exception as e:
            logging.debug('[-] Error retrieving org ID: {}'.format(e))
            return None


    ##########################################################################
    ##########################################################################
    ##
    ## get scopes
    ##
    ##########################################################################
    ##########################################################################


    def get_scope(self):

        try:

            if 'scope' in self.token_data:
                scope = self.token_data['scope']
                return scope
            else:
                return None

        except Exception as e:
            logging.debug('[-] Error retrieving scopes: {}'.format(e))
            return None

