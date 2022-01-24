##############################################################################
##############################################################################
##
##
##
##############################################################################
##############################################################################


from os import environ as env
import json
import datetime
import time
from auth0 import Auth0


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

token_data = auth0_mgmt.decode_token()

print(token_data)

data = json.loads(token_data)


'''
exp = None
iat = None

if 'exp' in data:
    exp = datetime.datetime.utcfromtimestamp(data['exp'])
    print('exp == {}'.format(data['exp']))

if 'iat' in data:
    iat = datetime.datetime.utcfromtimestamp(data['iat'])
    print('iat == {}'.format(data['iat']))


#print((exp-iat).seconds)
#print((exp-now).seconds)

i=0

while i < 20:

    now = datetime.datetime.utcnow()
    print('now == {}'.format(now))
    print('delta to expire == {}'.format((exp-now).seconds))
    print('delta from issue == {}'.format((now-iat).seconds))
    print('minutes to expire == {}'.format( ((exp-now).seconds/60) ))
    print('minutes from issue == {}'.format( ((now-iat).seconds/60) ))

#    if (exp-now).seconds > 600:
    if (now-iat).seconds > 600:
        break
    else:
        ##
        ## sleep for 1 minute
        ##
        print('Sleeping for 1 minute')
        time.sleep(60)

    i=i+1

'''