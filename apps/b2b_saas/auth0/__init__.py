###############################################################################
###############################################################################
##
##  TODO
##
###############################################################################
###############################################################################

# age of access token
# exponential backoff
# org cleanup job

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

##
## using dummy since this application is running on nginx + gunicorn
## which is already multiprocessed by default
##
import multiprocessing.dummy as multiprocessing

import jwt
from jwt import PyJWKClient

import logging

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='/var/log/auth0.log',
                    filemode='w')


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
        p.start()

    ##########################################################################
    ##########################################################################
    ##
    ## get token
    ##
    ##########################################################################
    ##########################################################################


    def get_token(self):

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
            logging.debug('[+] Sleeping for {}'.format(self.token_refresh_interval))
            time.sleep(self.token_refresh_interval)
            self.get_token()



    ##########################################################################
    ##########################################################################
    ##
    ## create organization
    ##
    ##########################################################################
    ##########################################################################


    def create_organization(self, data=None, kwargs=None):

        err = False

        required_fields = ['email', 'name']
        optional_fields = ['logo_url', 'primary_color', 'page_background_color', 'tier']


        for r in required_fields:
            if r not in data:
                err = True


        org_json = None
        org_data = None

        ##
        ## TODO: test that user has not already created an org w/ email
        ##

        if not err:

            email = data['email']
            name = data['name']

            if 'tier' in data:
                tier = data['tier']

            org_data = {}

            header = {'Authorization' : 'Bearer {}'.format(self.access_token)}

            if kwargs is not None:
                org_data = kwargs

            org_id = str(uuid.uuid4())

            org_data['name'] = org_id
            org_data['display_name'] = name
            org_data['metadata'] = {
                'origin_email' : email,
                'tier' : tier
            }


            ##
            ## add branding to the Org authentication experience
            ##
            branding = {}
            colors = {}
            if 'logo_url' in data:
                branding['logo_url'] = data['logo_url']

            if 'primary_color' in data:
                colors['primary'] = data['primary_color']

            if 'page_background_color' in data:
                colors['page_background'] = data['page_background_color']


            if len(branding) > 0:
                org_data['branding'] = branding

                if len(colors) > 0:
                    org_data['branding']['colors'] = colors

            logging.debug('[+] Request payload {} for'.format(org_data))

            url = '{}/organizations'.format(self.mgmt_endpoint)

            org_response = requests.post(url, json=org_data, headers=header)

            logging.debug('[+] Finished creating organization {} for {}'.format(name, email))

            org_json = org_response.json()

            logging.debug('[+] Organization JSON: {}'.format(org_json))

            ##
            ## return the new organization user ID
            ##
            #self.org_id = org_json['id']

        return org_json


    ##########################################################################
    ##########################################################################
    ##
    ## update organization
    ##
    ##########################################################################
    ##########################################################################


    def update_organization(self, org_id=None, kwargs=None):

        org_id = org_id
        kwargs = kwargs

        org_json = None
        org_data = None

        ##
        ## TODO: test that user has not already created an org w/ email
        ##

        if org_id is not None and kwargs is not None:

            org_data = {}

            header = {
                'Authorization' : 'Bearer {}'.format(self.access_token),
                'content-type': 'application/json'
            }

            if kwargs is not None:
                org_data = kwargs

            logging.debug('[+] Request payload for org {} update: {}'.format(org_id, org_data))

            url = '{}/organizations/{}'.format(self.mgmt_endpoint, org_id)

            org_response = requests.patch(url, json=org_data, headers=header)

            logging.debug('[+] Finished updating organization {}'.format(org_id))

            org_json = org_response.json()

            logging.debug('[+] Organization JSON: {}'.format(org_json))

        return org_json


    ##########################################################################
    ##########################################################################
    ##
    ## get organization
    ##
    ##########################################################################
    ##########################################################################


    def get_organization(self, org_id=None):

        org_id = org_id
        org_json = None
        org_data = None

        ##
        ## TODO: test that user has not already created an org w/ email
        ##

        if org_id is not None:

            header = {'Authorization' : 'Bearer {}'.format(self.access_token)}

            logging.debug('[+] Retrieving organization {}'.format(org_id))

            url = '{}/organizations/{}'.format(self.mgmt_endpoint, org_id)

            org_response = requests.get(url, headers=header)

            org_json = org_response.json()

            logging.debug('[+] Organization JSON for {}: {}'.format(org_id, org_json))

        return org_json


    ##########################################################################
    ##########################################################################
    ##
    ## get user by email
    ##
    ##########################################################################
    ##########################################################################


    def get_user_by_email(self, email=None):

        email = email
        req_data = {}
        res_data = None

        if email is not None:
            req_data['email'] = email
            header = {'Authorization' : 'Bearer {}'.format(self.access_token)}

            url = '{}/users-by-email?email={}'.format(self.mgmt_endpoint, email)

            logging.debug('[+] Getting user by email {}'.format(email))
            response = requests.get(url, headers=header)

            res_data = response.json()

            logging.debug('[+] User JSON: {}'.format(res_data))

        return res_data


    ##########################################################################
    ##########################################################################
    ##
    ## get connection
    ##
    ##########################################################################
    ##########################################################################


    def get_connection(self, name=None):

        ##
        ## only supports getting a connection by name
        ##

        name = name
        conn_data = {}
        conn_json = None

        if name is not None:
            conn_data['name'] = name
            header = {'Authorization' : 'Bearer {}'.format(self.access_token)}

            url = '{}/connections?name={}'.format(self.mgmt_endpoint, name)

            logging.debug('[+] Getting connection {}'.format(name))
            conn_response = requests.get(url, headers=header)

            conn_json = conn_response.json()

            logging.debug('[+] Connection JSON: {}'.format(conn_json))

            ##
            ## return the connection ID (should be array of length 1)
            ##
            #self.conn_id = conn_json[0]['id']

        return conn_json


    ##########################################################################
    ##########################################################################
    ##
    ## create connection
    ##
    ##########################################################################
    ##########################################################################


    def create_connection(self, *args, **kwargs):

        err = False

        req_data = None
        res_data = None


        required_fields = {
            'samlp' : [
                'name', 'strategy', 'sign_req_algo', 
                'sign_req_digest', 'signin_url', 'x509_cert'
            ]
        }

        optional_fields = {
            'samlp' : [
                'display_name', 'icon_url'
            ]
        }


        if 'strategy' not in kwargs:
            err = True


        for r in required_fields[kwargs['strategy']]:
            if r not in kwargs:
                err = True
                break

        if err:
            return None 


        if kwargs['strategy'] == 'samlp':

            ##
            ## See: https://auth0.com/docs/connections/enterprise/saml
            ##

            req_data = { 
                'strategy': kwargs['strategy'],
                'name': kwargs['name'],
                'options' : { 
                    'signInEndpoint': kwargs['signin_url'], 
                    'signatureAlgorithm': kwargs['sign_req_algo'],
                    'digestAlgorithm': kwargs['sign_req_digest'], 
                    'signingCert' : base64.b64encode(kwargs['x509_cert']).decode('ascii'),
                    'signSAMLRequest' : True
                    #'signOutEndpoint': '', 
                    #'fieldsMap': {}, 
                }
            }

            if 'icon_url' in kwargs:
                req_data['options']['icon_url'] = kwargs['icon_url']

            if 'display_name' in kwargs:
                req_data['display_name'] = kwargs['display_name']

            if 'metadata' in kwargs:
                req_data['metadata'] = kwargs['metadata']


        '''
        for o in optional_fields[kwargs['strategy']]:
            req_data[o] = kwargs[o]
        '''

        logging.debug('[+] Request Data: {}'.format(req_data))

        if req_data is not None:

            req_data['enabled_clients'] = [ self.client_id ]

            header = {'Authorization' : 'Bearer {}'.format(self.access_token)}
            url = '{}/connections'.format(self.mgmt_endpoint)
            logging.debug('[+] Creating connection {}'.format(req_data))

            response = requests.post(url, json=req_data, headers=header)

            res_data = response.json()
            logging.debug('[+] New Connection JSON: {}'.format(res_data))

            return res_data


    ##########################################################################
    ##########################################################################
    ##
    ## get role
    ##
    ##########################################################################
    ##########################################################################


    def get_roles(self, name=None):

        ##
        ## only supports getting a connection by name
        ##
        name = name
        res_data = None

        header = {'Authorization' : 'Bearer {}'.format(self.access_token)}

        if name is not None:

            logging.debug('[+] Getting role {}'.format(name))
            url = '{}/roles?name_filter={}'.format(self.mgmt_endpoint, name)

        else:
            logging.debug('[+] Getting all roles')
            url = '{}/roles'.format(self.mgmt_endpoint)



        res = requests.get(url, headers=header)
        res_data = res.json()
        logging.debug('[+] Role JSON: {}'.format(res_data))

        return res_data



    ##########################################################################
    ##########################################################################
    ##
    ## add connection to org
    ##
    ##########################################################################
    ##########################################################################


    def enable_org_connection( 
        self, 
        org_id=None, 
        conn_id=None,
        assign_membership_on_login=False
    ):

        ##
        ## enable a connection for an organization
        ##

        conn_id = conn_id
        org_id = org_id
        assign_membership_on_login = assign_membership_on_login

        conn_data = {}
        conn_json = None

        if conn_id is not None and org_id is not None:

            conn_data = {
                'connection_id': conn_id,
                'assign_membership_on_login': assign_membership_on_login
            }

            header = {'Authorization' : 'Bearer {}'.format(self.access_token)}

            url = '{}/organizations/{}/enabled_connections'.format(self.mgmt_endpoint, org_id)

            logging.debug('[+] Enabling connection {} for Organization'.format(conn_id, org_id))
            logging.debug('[+] Assign membership on login: {}'.format(assign_membership_on_login))
            conn_response = requests.post(url, json=conn_data, headers=header)

            conn_json = conn_response.json()

            logging.debug('[+] Connection JSON: {}'.format(conn_json))

        return conn_json


    ##########################################################################
    ##########################################################################
    ##
    ## create organization invitation
    ##
    ##########################################################################
    ##########################################################################


    def create_org_invite( self, org_id=None, data=None ):

        logging.debug('[+] Beginning invitation creation')

        org_id = org_id
        data = data

        org_json = None
        org_data = None

        if org_id is not None and data is not None:

            header = {'Authorization' : 'Bearer {}'.format(self.access_token)}

            logging.debug('[+] Invitation request payload {} for org {}'.format(data, org_id))

            url = '{}/organizations/{}/invitations'.format(self.mgmt_endpoint, org_id)

            invite_response = requests.post(url, json=data, headers=header)

            invite_json = invite_response.json()

            logging.debug('[+] Invitation JSON: {}'.format(invite_json))

        return invite_json


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


    '''
    ##########################################################################
    ##########################################################################
    ##
    ## get ID fields
    ##
    ##########################################################################
    ##########################################################################


    def get_id_fields(self):

        field_list= [
            'nickname', 'name', 'picture',
            'updated_at', 'email', 'email_verified',
            'iss', 'sub', 'aud', 'iat', 'exp',
            'nonce', 'org_id'
        ]

        try:


        except Exception as e:
            logging.debug('[-] Error retrieving scopes: {}'.format(e))
            return None
    '''
