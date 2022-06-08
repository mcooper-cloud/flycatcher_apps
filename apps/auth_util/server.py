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


endpoints = {
    'authorize' : 'https://{}/authorize'.format(AUTH0_AUTH_DOMAIN),
    'device_code' : 'https://{}/oauth/device/code'.format(AUTH0_AUTH_DOMAIN),
    #'token' : '{}/oauth/token'.format(AUTH0_BASE_URL),
    'token' : 'https://{}/oauth/token'.format(AUTH0_AUTH_DOMAIN),
    'user_info' : 'https://{}/userinfo'.format(AUTH0_AUTH_DOMAIN),
    'openidc_config' : 'https://{}/.well-known/openid-configuration'.format(AUTH0_AUTH_DOMAIN),
    'jwks' : 'https://{}/.well-known/jwks.json'.format(AUTH0_AUTH_DOMAIN)
}


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


'''
auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url='{}/oauth/token'.format(AUTH0_BASE_URL),
    authorize_url='{}/authorize'.format(AUTH0_AUTH_URL),
    client_kwargs={
#        'scope': 'openid profile email',
        'scope': DEFAULT_SCOPE
    },
)
'''

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=endpoints['token'],
    authorize_url=endpoints['authorize'],
    server_metadata_url=endpoints['openidc_config'],
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

    title_message = None

    form = LoginForm()

    if request.method == 'POST':

        if form.validate_on_submit():

            data = {}

            app_login_url = url_for('login')

            auth0_login_url = '{}/authorize'.format(AUTH0_AUTH_URL)
            auth0_login_url = '{}?response_type=code'.format(auth0_login_url)

            parameter_list = []

            #**
            #** Organization
            #**
            if form.organization_id.data:
                parameter_list.append('organization={}'.format(form.organization_id.data))


            #**
            #** Invitation
            #**
            if form.invitation_id.data:
                parameter_list.append('invitation={}'.format(form.invitation_id.data))

            #**
            #** Connection
            #**
            if form.connection_id.data:
                parameter_list.append('connection={}'.format(form.connection_id.data))

            #**
            #** Screen Hint
            #**
            if form.screen_hint.data:
                parameter_list.append('screen_hint={}'.format(form.screen_hint.data))

            '''
            #**
            #** Audience
            #**
            if form.audience.data:
                parameter_list.append('audience={}'.format(form.audience.data))

            else:
                parameter_list.append('audience={}'.format(AUTH0_AUDIENCE))
            '''

            #**
            #** Scope
            #**
            if form.scope.data:
                parameter_list.append('scope={}'.format(form.scope.data))
            else:
                parameter_list.append('scope={}'.format('openid+profile+email'))

            #**
            #** Redirect URI
            #**
            if form.redirect_uri.data:
                parameter_list.append('redirect_uri={}'.format(form.redirect_uri.data))
            else:
                parameter_list.append('redirect_uri={}'.format(AUTH0_CALLBACK_URL))


            if len(parameter_list) > 0:
                app_login_url = '{}?'.format(app_login_url)
                auth0_login_url = '{}&'.format(auth0_login_url)

                q = None
                for p in parameter_list:
                    if q is None:
                        q = p
                    else:
                        q = '{}&{}'.format(q,p)

                app_login_url = '{}{}'.format(app_login_url, q)
                auth0_login_url = '{}{}'.format(auth0_login_url, q)                


            data['app_login_url'] = app_login_url
            data['auth0_login_url'] = auth0_login_url

            return render_template('home.html', auth_data=data)

        else:
            title_message = 'Form did not validate'

            data = {
                'title_message' : title_message,
                'validation' : form.validate()
            }

            return render_template('home.html', error_data=data)

    else:
        ##
        ## TODO: remove signup form for authenticated users
        ##
        data = {
            'title_message' : title_message,
        }
        return render_template('home.html', form=form, data=data)


    return render_template('home.html')


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
    '''
    
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
#    return redirect('{}/v2/logout?{}'.format(auth0.api_base_url, urlencode(params)))
    return redirect('{}/v2/logout?{}'.format(AUTH0_AUTH_URL, urlencode(params)))


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
