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
#from flask import request _request_ctx_stack
from flask import request
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

from flask_bootstrap import Bootstrap

#import logging
#logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

from auth0 import Auth0, JWT
from forms import SignupForm, CreateConnectionForm, CreateInviteForm

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
AUTH0_DOMAIN = env.get('AUTH0_DOMAIN')
AUTH0_BASE_URL = 'https://{}'.format(AUTH0_DOMAIN)
AUTH0_AUDIENCE = env.get('AUTH0_AUDIENCE')

ENVIRONMENT_NAME = env.get('ENVIRONMENT_NAME')
PROJECT_NAME = env.get('PROJECT_NAME')
SYSTEM_NUMBER = env.get('SYSTEM_NUMBER')

WEB_APP_HTTP_URL = env.get('WEB_APP_HTTP_URL')

USER_PROFILE_KEY = 'profile'
JWT_PAYLOAD_KEY = 'jwt_payload'

SECRET_KEY = env.get('APP_SESSION_SECRET')

CONNECTION_NAME = '{}-{}-{}-customers'.format(PROJECT_NAME, ENVIRONMENT_NAME, SYSTEM_NUMBER)

org_admin_role = '{}-{}-{}-OrgAdmin'.format(PROJECT_NAME, ENVIRONMENT_NAME, SYSTEM_NUMBER)
org_member_role = '{}-{}-{}-OrgMember'.format(PROJECT_NAME, ENVIRONMENT_NAME, SYSTEM_NUMBER)


ROLE_LIST = [
    org_admin_role,
    org_member_role
]

custom_claim_namespace = WEB_APP_HTTP_URL

custom_claim_list = [
    'primary_org',
    'primary_org_name',
    'primary_org_display_name',
    'primary_org_tier',
    'primary_org_metadata',
    'current_org_name',
    'current_org_display_name',
    'current_org_tier',
    'current_org_metadata',
    'roles'
]

custom_claims = []
for c in custom_claim_list:
    custom_claims.append('{}/{}'.format(custom_claim_namespace, c))


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
    authorize_url='{}/authorize'.format(AUTH0_BASE_URL),
    client_kwargs={
        'scope': 'openid profile email',
    },
)

auth0_mgmt = Auth0( client_id=AUTH0_CLIENT_ID,
                    client_secret=AUTH0_CLIENT_SECRET,
                    auth0_domain=AUTH0_DOMAIN )

conn_data = auth0_mgmt.get_connection(name=CONNECTION_NAME)
conn_id = conn_data[0]['id']


role_id_list = {}

for r in ROLE_LIST:
    role_data = auth0_mgmt.get_roles(name=r)
    role_id_list[r] = role_data[0]['id']



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


def requires_org_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'token' not in session:

            return redirect('/login')

        else:

            data = get_token_data(
                token=session['token']['access_token'], 
                audience=AUTH0_AUDIENCE, 
                auth0_domain=AUTH0_DOMAIN,
                claims_list=custom_claims
            )

            if 'custom_claims' in data:
                custom_claim_data = data['custom_claims']
            else:
                custom_claim_data = {}

            role_claim_name = '{}/{}'.format(custom_claim_namespace, 'roles')

            if org_admin_role in custom_claim_data[role_claim_name]:
                return f(*args, **kwargs)
            else:
                return jsonify(error=str('The action your are attempting requires the Org Admin Role')), 403
    
    return decorated


##############################################################################
##############################################################################
##
## get token data
##
##############################################################################
##############################################################################


def get_token_data(token=None, audience=None, auth0_domain=None, claims_list=None):

    if token is not None:

        data = {}

        token_data = JWT( token=token, 
                          audience=audience, 
                          auth0_domain=auth0_domain )

        ##
        ##************************************************************************
        ##
        ## get custom claims from access token
        ##
        ##************************************************************************
        ##

        custom_claim_data = token_data.get_custom_claims( 
            claims_list=claims_list
        )

        if custom_claim_data is not None:
            data['custom_claims'] = custom_claim_data

        role_claim_name = '{}/{}'.format(custom_claim_namespace, 'roles')

        if role_claim_name in data['custom_claims']:
            data['roles'] = data['custom_claims'][role_claim_name]

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


# Controllers API
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/pricing/')
def pricing():
    return render_template('pricing.html')

@app.route('/docs/')
def docs():
    return render_template('docs.html')

@app.route('/about/')
def about():
    return render_template('about.html')

@app.route('/tac/')
def tac():
    return render_template('tac.html')

@app.route('/contact/')
def contact():
    return render_template('contact.html')


##############################################################################
##############################################################################
##
## callback
##
##############################################################################
##############################################################################


@app.route('/callback/')
def callback_handling():

    tier = request.args.get('tier')
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

    if tier is not None:
        session[USER_PROFILE_KEY]['tier'] = tier

    return redirect(redirect_uri)


##############################################################################
##############################################################################
##
## signup
##
##############################################################################
##############################################################################


@app.route('/signup/', methods=['GET', 'POST'])
def signup():

    title_message = None

    tier = request.args.get('tier')

    form = SignupForm()

    title_message = 'Join HyperUnicorn'

    if request.method == 'POST':

        if form.validate_on_submit():

            organization = form.organization.data
            email = form.email.data.lower()
            title_message = 'Please check your inbox and confirm your email address'

            ##
            ## create Auth0 Org and perform invite
            ##


            '''
            user = auth0_mgmt.get_user_by_email(email=email)

            if len(list(user)) > 0:
                ##
                ## user already exists ... reroute to login prompt
                ##
                title_message = 'The email address you provided already exists in our system.'

                data = {
                    'title_message' : title_message,
                    'user_exists' : True
                }

                return render_template('signup.html', data=data)
            '''

            org_data = auth0_mgmt.create_organization(email=email, name=organization, tier=tier)

            org_id = org_data['id']
            session['org_id'] = org_id

            ##
            ## associate the global connection w/ the org
            ##
            conn_enable = auth0_mgmt.enable_org_connection(org_id=org_id, conn_id=conn_id)

            app_metadata = {
                'primary_org' : org_id
            }

            ##
            ## Add OrgAdmin role to invite
            ##
            admin_role = '{}-{}-OrgAdmin'.format(PROJECT_NAME, ENVIRONMENT_NAME)
            role_id = role_id_list[admin_role]

            invite_data = {
                'invitee' : {'email' : email}, 
                'inviter' : {'name' : '{}-{}'.format(PROJECT_NAME, ENVIRONMENT_NAME)},
                'app_metadata' : app_metadata,
                'roles' : [role_id],
                'client_id' : AUTH0_CLIENT_ID,
                'send_invitation_email' : True
            }

            invite = auth0_mgmt.create_org_invite( org_id=org_id, data=invite_data )

            data = {
                'title_message' : title_message,
                'tier' : tier,
                'org_id' : org_data['id']
            }

            ##
            ## TODO: 
            ##      - create database
            ##

            return render_template('signup.html', data=data)

        else:
            title_message = 'Form did not validate'

            data = {
                'title_message' : title_message,
                'tier' : tier,
            }

            return render_template('signup.html', data=data)

    else:
        ##
        ## TODO: remove signup form for authenticated users
        ##
        data = {
            'title_message' : title_message,
            'tier' : tier
        }
        return render_template('signup.html', form=form, data=data)


##############################################################################
##############################################################################
##
## login
##
##############################################################################
##############################################################################


@app.route('/login/')
def login():

    signup = request.args.get('signup')
    tier = request.args.get('tier')
    organization = request.args.get('organization')
    organization_name  = request.args.get('organization_name')
    invitation = request.args.get('invitation')
    connection = request.args.get('connection')
    callback_uri = request.args.get('callback_uri')

    SCREEN_HINT=None
    if signup is not None:
        SCREEN_HINT='signup'

    REDIRECT_URI = AUTH0_CALLBACK_URL

    if tier is not None:
        REDIRECT_URI = '{}?tier={}'.format(REDIRECT_URI, tier)

    if callback_uri is not None:
        REDIRECT_URI = '{}?callback_uri={}'.format(REDIRECT_URI, callback_uri)


    '''
    if invitation is not None:
        ##
        ## new user has just been invited ... but possibly already has an Auth0 user profile
        ## so we don't really know whether to show screen_hint=signup or prompt=login
        ##
        ##      ... we could make a call to the Auth0 API to lookup the user by email
        ##
    '''

    return auth0.authorize_redirect( redirect_uri=REDIRECT_URI, 
                                     audience=AUTH0_AUDIENCE, 
                                     screen_hint=SCREEN_HINT,
                                     organization=organization,
                                     invitation=invitation )


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
    return redirect('{}/v2/logout?{}'.format(auth0.api_base_url, urlencode(params)))


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
        auth0_domain=AUTH0_DOMAIN,
        claims_list=custom_claims
    )

    return render_template( 
        'dash/dashboard.html',
        session=session,
        data=data 
    )


##############################################################################
##############################################################################
##
## org dashboard
##
##############################################################################
##############################################################################


@app.route('/dashboard/myorg/')
@requires_auth
def org_dashboard():

    data = get_token_data(
        token=session['token']['access_token'], 
        audience=AUTH0_AUDIENCE, 
        auth0_domain=AUTH0_DOMAIN,
        claims_list=custom_claims
    )

    if 'custom_claims' in data:
        custom_claim_data = data['custom_claims']
    else:
        custom_claim_data = {}

    ##
    ##************************************************************************
    ##
    ## create org login URI
    ##
    ##************************************************************************
    ##

    primary_org_claim = '{}/{}'.format(custom_claim_namespace, 'primary_org')

    primary_claim_list = [
        'primary_org_name',
        'primary_org_display_name',
        'primary_org_metadata',
        'primary_org_tier'
    ]

    data['primary_claim_list'] = primary_claim_list

    for p in primary_claim_list:
        claim = '{}/{}'.format(custom_claim_namespace, p)
        if claim in custom_claim_data:
            data[p] = custom_claim_data[claim]

    current_claim_list = [
        'current_org_name',
        'current_org_display_name',
        'current_org_metadata',
        'current_org_tier',
    ]

    data['current_claim_list'] = current_claim_list

    for c in current_claim_list:
        claim = '{}/{}'.format(custom_claim_namespace, c)
        if claim in custom_claim_data:
            data[c] = custom_claim_data[claim]


    login_uri = None
    if 'org_id' in session[JWT_PAYLOAD_KEY]:
        login_uri = '{}{}?organization={}'.format(WEB_APP_HTTP_URL, url_for('login'), session[JWT_PAYLOAD_KEY]['org_id'])

    elif primary_org_claim in custom_claim_data:
        ##
        ## if the user didn't login w/ an org ... then give them a link
        ##
        org_id = custom_claim_data[primary_org_claim]
        login_uri = '{}{}?organization={}'.format(WEB_APP_HTTP_URL, url_for('login'), org_id)

    else:
        login_uri = '{}{}'.format(WEB_APP_HTTP_URL, url_for('login'))


    if login_uri is not None:
        data['login_uri'] = login_uri

    '''
    data['project_name'] = PROJECT_NAME    
    data['environment'] = ENVIRONMENT_NAME    
    data['system_number'] = SYSTEM_NUMBER 
    '''


    if 'roles' in data and org_admin_role in data['roles']:
        data['is_org_admin'] = True
    else:
        data['is_org_admin'] = False


    return render_template( 
        'dash/myorg.html',
        session=session,
        data=data 
    )



##############################################################################
##############################################################################
##
## profile dashboard
##
##############################################################################
##############################################################################


@app.route('/dashboard/myprofile/')
@requires_auth
def profile_dashboard():

    data = get_token_data(
        token=session['token']['access_token'], 
        audience=AUTH0_AUDIENCE, 
        auth0_domain=AUTH0_DOMAIN,
        claims_list=custom_claims
    )

    return render_template( 
        'dash/myprofile.html',
        session=session,
        data=data 
    )



##############################################################################
##############################################################################
##
## add ons dashboard
##
##############################################################################
##############################################################################


@app.route('/dashboard/addons/')
@requires_auth
def addons_dashboard():

    data = get_token_data(
        token=session['token']['access_token'], 
        audience=AUTH0_AUDIENCE, 
        auth0_domain=AUTH0_DOMAIN,
        claims_list=custom_claims
    )

    org_metadata_claim = '{}/{}'.format(custom_claim_namespace, 'current_org_metadata')

    if 'custom_claims' in data:
        custom_claim_data = data['custom_claims']
    else:
        custom_claim_data = {}

    if org_metadata_claim in custom_claim_data:
        org_metadata = custom_claim_data[org_metadata_claim]
        data['org_metadata'] = org_metadata

    if 'roles' in data and org_admin_role in data['roles']:
        data['is_org_admin'] = True
    else:
        data['is_org_admin'] = False

    return render_template( 
        'dash/addons.html',
        session=session,
        data=data 
    )


##############################################################################
##############################################################################
##
## add ons dashboard extended paths
##
##############################################################################
##############################################################################


@app.route('/dashboard/addons/<path>/')
@requires_auth
@requires_org_admin
def addons_extended_dashboard(path):

    allowed_addons = [
        'teams_addon',
        'security_addon',
        'campaigns_addon'
    ]

    data = get_token_data(
        token=session['token']['access_token'], 
        audience=AUTH0_AUDIENCE, 
        auth0_domain=AUTH0_DOMAIN,
        claims_list=custom_claims
    )

    ##
    ##  1. get the add on name
    ##  2. get the user's org
    ##  3. add the add on to org metadata
    ##  4. re-new token w/ addons
    ##

    addon = path

    if addon not in allowed_addons:
        return render_template( 
            'dash/addons.html',
            session=session,
            data=data 
        )


    if 'org_id' in session[JWT_PAYLOAD_KEY]:
        org_id = session[JWT_PAYLOAD_KEY]['org_id']
        org_data = auth0_mgmt.get_organization(org_id=org_id)
        data['org_data'] = org_data

        if 'metadata' in org_data:
            if 'addons' in org_data['metadata']:

                if addon not in org_data['metadata']['addons']:
                    org_data['metadata'][str(addon)] = 'true'

            else:
                org_data['metadata'][str(addon)] = 'true'

        update_data = {
            'metadata' : org_data['metadata']
        }

        org_data = auth0_mgmt.update_organization(org_id=org_id, kwargs=update_data)
        data['new_org_data'] = org_data


    login_uri = '/login?organization={}'.format(org_id,)
    login_uri = '{}&callback_uri={}'.format(login_uri, url_for('addons_dashboard'))


    return redirect(login_uri)


    '''
    return render_template( 
        'dash/addons.html',
        session=session,
        data=data 
    )
    '''


##############################################################################
##############################################################################
##
## create connection
##
##############################################################################
##############################################################################


@app.route('/dashboard/createconn/', methods=['GET', 'POST'])
@requires_auth
@requires_org_admin
def create_connection():


    data = get_token_data(
        token=session['token']['access_token'], 
        audience=AUTH0_AUDIENCE, 
        auth0_domain=AUTH0_DOMAIN,
        claims_list=custom_claims
    )

    if 'custom_claims' in data:
        custom_claim_data = data['custom_claims']
    else:
        custom_claim_data = {}


    if 'org_id' in session[JWT_PAYLOAD_KEY]:
        org_id = session[JWT_PAYLOAD_KEY]['org_id']


    form = CreateConnectionForm()

    if request.method == 'POST':

        if form.validate_on_submit():

            conn_name = form.conn_name.data
            conn_strategy = form.conn_strategy.data
            sign_req_algo = form.sign_req_algo.data
            sign_req_digest = form.sign_req_digest.data
            signin_url = form.signin_url.data
            x509_cert = form.x509_cert.data.read()

            if form.assign_membership_on_login.data == 'True':
                assign_membership_on_login = True
            else:
                assign_membership_on_login = False


            data = {
                'name' : conn_name,
                'strategy' : conn_strategy,
                'sign_req_algo' : sign_req_algo,
                'sign_req_digest' : sign_req_digest,
                'signin_url' : signin_url,
                'x509_cert' : x509_cert,
                'metadata': {
                    'org_id' : org_id
                }
            }

            connection = auth0_mgmt.create_connection(**data)

            conn_id = connection['id']

            conn_enable = auth0_mgmt.enable_org_connection(
                org_id=org_id, 
                conn_id=conn_id,
                assign_membership_on_login=assign_membership_on_login
            )


            auth0_domain_pre = AUTH0_DOMAIN.split('.')[0]
            data['connection_id'] = conn_id
            data['audience_uri'] = 'urn:auth0:{}:{}'.format(auth0_domain_pre, conn_name)
            data['sso_url'] = AUTH0_CALLBACK_URL
            data['recipient_url'] = AUTH0_CALLBACK_URL
            data['destination_url'] = AUTH0_CALLBACK_URL

            return render_template('dash/connection.html', data=data)

        else:

            title_message = 'Form did not validate'
            data = {
                'title_message' : title_message,
                'form_errors' : form.errors
            }

            return render_template('dash/connection.html', data=data)

    else:
        data = {}
        return render_template('dash/connection.html', form=form, data=data)



##############################################################################
##############################################################################
##
## create connection
##
##############################################################################
##############################################################################


@app.route('/dashboard/invite/', methods=['GET', 'POST'])
@requires_auth
@requires_org_admin
def create_invitation():


    data = {}

    token_data = get_token_data(
        token=session['token']['access_token'], 
        audience=AUTH0_AUDIENCE, 
        auth0_domain=AUTH0_DOMAIN,
        claims_list=custom_claims
    )

    form = CreateInviteForm()

    if request.method == 'POST':

        if form.validate_on_submit():

            if 'email' in session[USER_PROFILE_KEY]:
                data['inviter'] = {'name' : session[USER_PROFILE_KEY]['email']}
            else:
                ##
                ## TODO: fix this
                ##
                data['inviter'] = {'name' : 'foo'}

            email = form.email.data

            ##
            ## because this function requires OrgAdmin role
            ## which is only assigned to org members after
            ## an organizations authentication, then an org_id
            ## must be present in the token payload
            ##
            org_id = token_data['org_id']

            data['invitee'] = {
                'email' : email
            }

            data['client_id'] = AUTH0_CLIENT_ID
            data['send_invitation_email'] = True

            member_role = '{}-{}-OrgMember'.format(PROJECT_NAME, ENVIRONMENT_NAME)
            role_id = role_id_list[member_role]

            data['roles'] = [role_id]

            invite = auth0_mgmt.create_org_invite(org_id=org_id, data=data)

            data['invite_data'] = invite

            return render_template('dash/invite.html', data=data)

        else:

            title_message = 'Form did not validate'
            data = {
                'title_message' : title_message,
                'form_errors' : form.errors
            }

            return render_template('dash/invite.html', data=data)

    else:
        data = {}
        return render_template('dash/invite.html', form=form, data=data)


##############################################################################
##############################################################################
##
## support
##
##############################################################################
##############################################################################


@app.route('/support/')
@requires_auth
def support():
    return render_template( 'support.html')


##############################################################################
##############################################################################
##
## main
##
##############################################################################
##############################################################################


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 5000))
