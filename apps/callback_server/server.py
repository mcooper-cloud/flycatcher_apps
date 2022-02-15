'''

Python Flask WebApp Auth0 integration example

'''

##############################################################################
##############################################################################
##
##
##
##############################################################################
##############################################################################


import os
import binascii

from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from flask import Flask
from flask import jsonify
from flask import redirect
from flask import request
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

from flask_bootstrap import Bootstrap

from auth0 import Auth0, JWT

##############################################################################
##############################################################################
##
##
##
##############################################################################
##############################################################################


AUTH0_CALLBACK_URL = env.get('AUTH0_CALLBACK_URL')
AUTH0_CLIENT_ID = env.get('AUTH0_CLIENT_ID')
AUTH0_CLIENT_SECRET = env.get('AUTH0_CLIENT_SECRET')

AUTH0_AUTH_DOMAIN = env.get('AUTH0_AUTH_DOMAIN')
AUTH0_MGMT_DOMAIN = env.get('AUTH0_MGMT_DOMAIN')

AUTH0_BASE_URL = 'https://{}'.format(AUTH0_MGMT_DOMAIN)
AUTH0_AUTH_URL = 'https://{}'.format(AUTH0_AUTH_DOMAIN)
AUTH0_AUDIENCE = env.get('AUTH0_AUDIENCE')

ENVIRONMENT_NAME = env.get('ENVIRONMENT_NAME')
PROJECT_NAME = env.get('PROJECT_NAME')
SYSTEM_NUMBER = env.get('SYSTEM_NUMBER')

USER_PROFILE_KEY = 'profile'
JWT_PAYLOAD_KEY = 'jwt_payload'

SECRET_KEY = env.get('APP_SESSION_SECRET')

GLOBAL_SCOPE = 'openid profile email'


##############################################################################
##############################################################################
##
##
##
##############################################################################
##############################################################################


app = Flask(__name__, static_url_path='/static', static_folder='./static')
app.secret_key = SECRET_KEY
app.debug = True

bootstrap = Bootstrap(app)

@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url='{}/oauth/token'.format(AUTH0_BASE_URL),
    authorize_url='{}/authorize'.format(AUTH0_AUTH_URL),
    client_kwargs={
        'scope': 'openid profile email',
    },
)

auth0_mgmt = Auth0( client_id=AUTH0_CLIENT_ID,
                    client_secret=AUTH0_CLIENT_SECRET,
                    auth0_domain=AUTH0_MGMT_DOMAIN )


##############################################################################
##############################################################################
##
## auth decorators
##
##############################################################################
##############################################################################


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if USER_PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


##############################################################################
##############################################################################
##
## generic routes
##
##############################################################################
##############################################################################


@app.route('/', methods=['GET'])
@requires_auth
def home():
    redirect_uri = '/callback'
    return redirect(redirect_uri)


##############################################################################
##############################################################################
##
## callback
##
##############################################################################
##############################################################################


@app.route('/callback/')
@requires_auth
def callback_handling():

    callback_uri = request.args.get('callback_uri')

    if callback_uri is not None:
        redirect_uri = callback_uri
    else:
        redirect_uri = '/dashboard'

    return redirect(redirect_uri)


##############################################################################
##############################################################################
##
## login
##
##############################################################################
##############################################################################


@app.route('/login/')
def login():

    screen_hint = request.args.get('screen_hint')
    organization = request.args.get('organization')
    organization_name  = request.args.get('organization_name')
    invitation = request.args.get('invitation')
    connection = request.args.get('connection')
    callback_uri = request.args.get('callback_uri')
    audience = request.args.get('audience')

    if request.args.get('scope') is not None:
        scope = request.args.get('scope')
    else:
        scope = GLOBAL_SCOPE

    SCREEN_HINT=None
    if screen_hint is not None:
        SCREEN_HINT='signup'


    REDIRECT_URI = AUTH0_CALLBACK_URL


    if callback_uri is not None:
        REDIRECT_URI = '{}?callback_uri={}'.format(REDIRECT_URI, callback_uri)


    if audience is not None:
        AUTH0_AUDIENCE = audience

    
    return auth0.authorize_redirect( redirect_uri=REDIRECT_URI, 
                                     audience=AUTH0_AUDIENCE, 
                                     screen_hint=SCREEN_HINT,
                                     organization=organization,
                                     invitation=invitation,
                                     scope=scope )


##############################################################################
##############################################################################
##
## logout
##
##############################################################################
##############################################################################


@app.route('/logout/')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect('{}/v2/logout?{}'.format(AUTH0_AUTH_URL, urlencode(params)))


##############################################################################
##############################################################################
##
## main
##
##############################################################################
##############################################################################


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 5000))
