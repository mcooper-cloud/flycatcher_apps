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
from forms import LoginForm

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

#WEB_APP_HTTP_URL = env.get('WEB_APP_HTTP_URL')

USER_PROFILE_KEY = 'profile'
JWT_PAYLOAD_KEY = 'jwt_payload'

SECRET_KEY = env.get('APP_SESSION_SECRET')

DEFAULT_SCOPE = 'openid profile email'

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
        'scope': DEFAULT_SCOPE
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
## get token data
##
##############################################################################
##############################################################################


def get_token_data(token=None, audience=None, auth0_domain=None):

    if token is not None:

        data = {}

        token_data = JWT( token=token, 
                          audience=audience, 
                          auth0_domain=auth0_domain )


        ##
        ##************************************************************************
        ##
        ## get permissions from access token
        ##
        ##************************************************************************
        ##

        permissions = token_data.get_permissions()

        if permissions is not None:
            data['permissions'] = permissions


        ##
        ##************************************************************************
        ##
        ## get org_id from access token
        ##
        ##************************************************************************
        ##

        org_id = token_data.get_org_id()

        if org_id is not None:
            data['org_id'] = org_id


        ##
        ##************************************************************************
        ##
        ## get scopes from access token
        ##
        ##************************************************************************
        ##

        scope = token_data.get_scope()


        if scope is not None:
            data['scope'] = scope


        return data

    else:
        return None        


##############################################################################
##############################################################################
##
## generic routes
##
##############################################################################
##############################################################################


@app.route('/', methods=['GET', 'POST'])
def home():

    return render_template('home.html')

'''
##############################################################################
##############################################################################
##
## callback
##
##############################################################################
##############################################################################


@app.route('/callback/')
def callback_handling():

    callback_uri = request.args.get('callback_uri')

    if callback_uri is not None:
        redirect_uri = callback_uri
    else:
        redirect_uri = '/dashboard'

    token = auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    session[JWT_PAYLOAD_KEY] = userinfo
    session[USER_PROFILE_KEY] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture'],
        'email': userinfo['email']
    }

    session['token'] = token

    return redirect(redirect_uri)
'''


##############################################################################
##############################################################################
##
## signup
##
##############################################################################
##############################################################################


@app.route('/signup/')
def signup():

    title_message = None

    form = SignupForm()

    if request.method == 'POST':

        if form.validate_on_submit():

            data = {}
            parameter_list = []

            username = None
            email = None
            password = None

            #**
            #** username
            #**
            if form.username.data:
                username = form.username.data

            #**
            #** email
            #**
            if form.email.data:
                email = form.email.data

            #**
            #** password
            #**
            if form.pwd.data:
                pwd = form.pwd.data

            return render_template('auth.html', auth_data=data)

        else:
            title_message = 'Form did not validate'

            data = {
                'title_message' : title_message,
                'validation' : form.validate()
            }

            return render_template('auth.html', error_data=data)

    else:
        ##
        ## TODO: remove signup form for authenticated users
        ##
        data = {
            'title_message' : title_message,
        }
        return render_template('auth.html', form=form, data=data)


    return render_template('auth.html')




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
#    audience = request.args.get('audience')


    if request.args.get('scope') is not None:
        scope = request.args.get('scope')
    else:
        scope = DEFAULT_SCOPE


    SCREEN_HINT=None
    if screen_hint is not None:
        SCREEN_HINT = screen_hint


    REDIRECT_URI = AUTH0_CALLBACK_URL

    if callback_uri is not None:
        REDIRECT_URI = '{}?callback_uri={}'.format(REDIRECT_URI, callback_uri)

    '''
    if audience is not None:
        AUTH0_AUDIENCE = audience
    
    return auth0.authorize_redirect( redirect_uri=REDIRECT_URI, 
                                     audience=AUTH0_AUDIENCE, 
                                     screen_hint=SCREEN_HINT,
                                     organization=organization,
                                     invitation=invitation,
                                     scope=scope )
    '''
    return


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
#    return redirect('{}/v2/logout?{}'.format(auth0.api_base_url, urlencode(params)))
#    return redirect('{}/v2/logout?{}'.format(AUTH0_AUTH_URL, urlencode(params)))

    return


##############################################################################
##############################################################################
##
## dashboard
##
##############################################################################
##############################################################################


@app.route('/dashboard/')
@requires_auth
def dashboard():

    data = get_token_data(
        token=session['token']['access_token'], 
        audience=AUTH0_AUDIENCE, 
        auth0_domain=AUTH0_AUTH_DOMAIN
    )

    return render_template( 
        'dashboard.html',
        session=session,
        data=data 
    )



##############################################################################
##############################################################################
##
## main
##
##############################################################################
##############################################################################


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 5000))
