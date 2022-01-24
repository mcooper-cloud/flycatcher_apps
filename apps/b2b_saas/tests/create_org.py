##############################################################################
##############################################################################
##
##
##
##############################################################################
##############################################################################

from os import environ as env
from ../auth0 import Auth0

##############################################################################
##############################################################################
##
##
##
##############################################################################
##############################################################################


AUTH0_CLIENT_ID = env.get('AUTH0_CLIENT_ID')
AUTH0_CLIENT_SECRET = env.get('AUTH0_CLIENT_SECRET')
AUTH0_DOMAIN = env.get('AUTH0_DOMAIN')
AUTH0_BASE_URL = 'https://{}'.format(AUTH0_DOMAIN)
AUTH0_AUDIENCE = env.get('AUTH0_AUDIENCE')

ENVIRONMENT_NAME = env.get('ENVIRONMENT_NAME')
PROJECT_NAME = env.get('PROJECT_NAME')
SYSTEM_NUMBER = env.get('SYSTEM_NUMBER')

SECRET_KEY = env.get('APP_SESSION_SECRET')

CONNECTION_NAME = '{}-{}-customers'.format(PROJECT_NAME, ENVIRONMENT_NAME)

email='matt.cooper@auth0.com'
organization = 'testorg'
tier='ent'

auth0_mgmt = Auth0( client_id=AUTH0_CLIENT_ID,
                    client_secret=AUTH0_CLIENT_SECRET,
                    auth0_domain=AUTH0_DOMAIN )

conn_data = auth0_mgmt.get_connection(name=CONNECTION_NAME)
conn_id = conn_data[0]['id']

print('Connection ID: {}'.format(conn_id))

org_data = auth0_mgmt.create_organization(email=email, name=organization, tier=tier)

print(org_data)

print(org_data['id'])

conn_enable = auth0_mgmt.enable_org_connection(org_id=org_data['id'], conn_id=conn_id)
