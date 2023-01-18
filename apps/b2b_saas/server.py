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

from auth0 import Auth0, JWT
from forms import SignupForm, CreateSAMLConnectionForm, CreateInviteForm


import logging

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='/var/log/server.log',
                    filemode='w')

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

LOGO_URL = env.get('LOGO_URL')
PAGE_BACKGROUND_COLOR = env.get('PAGE_BACKGROUND_COLOR')
PRIMARY_COLOR = env.get('PRIMARY_COLOR')

AUTH0_BASE_URL = 'https://{}'.format(AUTH0_MGMT_DOMAIN)
AUTH0_AUTH_URL = 'https://{}'.format(AUTH0_AUTH_DOMAIN)

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

connection_strategies = {
    'SAML' : 'samlp',
}

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


endpoints = {
    'authorize' : 'https://{}/authorize'.format(AUTH0_AUTH_DOMAIN),
    'device_code' : 'https://{}/oauth/device/code'.format(AUTH0_AUTH_DOMAIN),
    'token' : 'https://{}/oauth/token'.format(AUTH0_AUTH_DOMAIN),
    'user_info' : 'https://{}/userinfo'.format(AUTH0_AUTH_DOMAIN),
    'openidc_config' : 'https://{}/.well-known/openid-configuration'.format(AUTH0_AUTH_DOMAIN),
    'jwks' : 'https://{}/.well-known/jwks.json'.format(AUTH0_AUTH_DOMAIN)
}

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

##
## Auth0 authentication API client
##
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

##
## Auth0 Management API client
##
auth0_mgmt = Auth0( client_id=AUTH0_CLIENT_ID,
                    client_secret=AUTH0_CLIENT_SECRET,
                    auth0_domain=AUTH0_MGMT_DOMAIN )


##
## get the primary Auth0 DB connection ID
##
conn_data = auth0_mgmt.get_connection(name=CONNECTION_NAME)
conn_id = conn_data[0]['id']

##
## get a list of role IDs
##
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
                auth0_domain=AUTH0_AUTH_DOMAIN,
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

@app.route('/')
def home():
    return render_template('home/home.html')

@app.route('/pricing/')
def pricing():
    return render_template('home/pricing.html')

@app.route('/docs/')
def docs():
    return render_template('home/docs.html')

@app.route('/about/')
def about():
    return render_template('home/about.html')

@app.route('/tac/')
def tac():
    return render_template('home/tac.html')

@app.route('/contact/')
def contact():
    return render_template('home/contact.html')


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
    org_data = {}

    org_data['tier'] = request.args.get('tier')

    form = SignupForm()

    title_message = 'Join HyperUnicorn'

    if request.method == 'POST':

        if form.validate_on_submit():

            org_data['name'] = form.organization.data
            org_data['email'] = form.email.data.lower()
            title_message = 'Please check your inbox and confirm your email address'

            org_data['logo_url'] = LOGO_URL
            org_data['page_background_color'] = PAGE_BACKGROUND_COLOR
            org_data['primary_color'] = PRIMARY_COLOR

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

            org_res_data = auth0_mgmt.create_organization(data=org_data)

            org_id = org_res_data['id']
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
            admin_role = '{}-{}-{}-OrgAdmin'.format(PROJECT_NAME, ENVIRONMENT_NAME, SYSTEM_NUMBER)
            role_id = role_id_list[admin_role]

            invite_data = {
                'invitee' : {'email' : org_data['email']}, 
                'inviter' : {'name' : '{}-{}-{}'.format(PROJECT_NAME, ENVIRONMENT_NAME, SYSTEM_NUMBER)},
                'app_metadata' : app_metadata,
                'roles' : [role_id],
                'client_id' : AUTH0_CLIENT_ID,
                'send_invitation_email' : True
            }

            invite = auth0_mgmt.create_org_invite( org_id=org_id, data=invite_data )

            data = {
                'title_message' : title_message,
                'tier' : org_data['tier'],
                'org_id' : org_id
            }

            ##
            ## TODO: 
            ##      - create database
            ##

            return render_template('home/signup.html', data=data)

        else:
            title_message = 'Form did not validate'

            data = {
                'title_message' : title_message,
                'tier' : org_data['tier'],
            }

            return render_template('home/signup.html', data=data)

    else:
        ##
        ## TODO: remove signup form for authenticated users
        ##
        data = {
            'title_message' : title_message,
            'tier' : org_data['tier']
        }
        return render_template('home/signup.html', form=form, data=data)


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
        ##      ... or we could just use a database
        ##
    '''

    return auth0.authorize_redirect( redirect_uri=REDIRECT_URI, 
                                     audience=AUTH0_AUDIENCE, 
                                     screen_hint=SCREEN_HINT,
                                     connection=connection,
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
        auth0_domain=AUTH0_AUTH_DOMAIN,
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
        auth0_domain=AUTH0_AUTH_DOMAIN,
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
    ##
    ## these values could be added to Auth0 metadata
    ##
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
        auth0_domain=AUTH0_AUTH_DOMAIN,
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
        auth0_domain=AUTH0_AUTH_DOMAIN,
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
        auth0_domain=AUTH0_AUTH_DOMAIN,
        claims_list=custom_claims
    )

    ##
    ##  1. get the add on name
    ##  2. get the user's org
    ##  3. add the add on to org metadata
    ##  4. re-new token w/ custom claims for addons
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


##############################################################################
##############################################################################
##
## create connection
##
##############################################################################
##############################################################################


@app.route('/dashboard/createconn/', methods=['GET'])
@requires_auth
@requires_org_admin
def create_connection():

    data = get_token_data(
        token=session['token']['access_token'], 
        audience=AUTH0_AUDIENCE, 
        auth0_domain=AUTH0_AUTH_DOMAIN,
        claims_list=custom_claims
    )

    if 'custom_claims' in data:
        custom_claim_data = data['custom_claims']
    else:
        custom_claim_data = {}


    if 'org_id' in session[JWT_PAYLOAD_KEY]:
        org_id = session[JWT_PAYLOAD_KEY]['org_id']

    if 'roles' in data and org_admin_role in data['roles']:
        data['is_org_admin'] = True
    else:
        data['is_org_admin'] = False


    return render_template('dash/connection.html', data=data)


##############################################################################
##############################################################################
##
## create SAML connection
##
##############################################################################
##############################################################################


@app.route('/dashboard/createconn/saml', methods=['GET', 'POST'])
@requires_auth
@requires_org_admin
def create_saml_connection():

    data = get_token_data(
        token=session['token']['access_token'], 
        audience=AUTH0_AUDIENCE, 
        auth0_domain=AUTH0_AUTH_DOMAIN,
        claims_list=custom_claims
    )

    if 'custom_claims' in data:
        custom_claim_data = data['custom_claims']
    else:
        custom_claim_data = {}


    if 'org_id' in session[JWT_PAYLOAD_KEY]:
        org_id = session[JWT_PAYLOAD_KEY]['org_id']


    form = CreateSAMLConnectionForm()

    if request.method == 'POST':

        if form.validate_on_submit():

            conn_name = form.conn_name.data
            conn_id = form.conn_id.data
            icon_url = form.icon_url.data

            ##
            ## this connection form is specific to SAML connections
            ## so it is unncessary to allow the user to select a strategy
            ## if this changes ... uncomment the line below:
            ##
            #conn_strategy = form.conn_strategy.data
            conn_strategy = connection_strategies['SAML']

            sign_req_digest = form.sign_req_digest.data
            sign_req_algo = form.sign_req_algo.data
            signin_url = form.signin_url.data
            x509_cert = form.x509_cert.data.read()

            if form.assign_membership_on_login.data == 'True':
                assign_membership_on_login = True
            else:
                assign_membership_on_login = False

            data = {
                'name' : conn_id,
                'display_name' : conn_name,
                'strategy' : conn_strategy,
                'sign_req_algo' : sign_req_algo,
                'sign_req_digest' : sign_req_digest,
                'signin_url' : signin_url,
                'x509_cert' : x509_cert,
                'metadata': {
                    'org_id' : org_id
                }
            }

            data['show_as_button'] = 'false'

            if not icon_url == '':
                data['show_as_button'] = 'true'
                data['icon_url'] = icon_url


            connection = auth0_mgmt.create_connection(**data)

            conn_id = connection['id']

            conn_enable = auth0_mgmt.enable_org_connection(
                org_id=org_id, 
                conn_id=conn_id,
                assign_membership_on_login=assign_membership_on_login
            )

            auth0_domain_pre = AUTH0_AUTH_DOMAIN.split('.')[0]
            data['connection_id'] = conn_id
            data['audience_uri'] = 'urn:auth0:{}:{}'.format(auth0_domain_pre, conn_id)
            data['sso_url'] = AUTH0_CALLBACK_URL
            data['recipient_url'] = AUTH0_CALLBACK_URL
            data['destination_url'] = AUTH0_CALLBACK_URL

            return render_template('dash/connection_saml.html', data=data)

        else:

            title_message = 'Form did not validate'
            data = {
                'title_message' : title_message,
                'form_errors' : form.errors
            }

            return render_template('dash/connection_saml.html', data=data)

    else:
        data = {}
        return render_template('dash/connection_saml.html', form=form, data=data)



##############################################################################
##############################################################################
##
## create invitation
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
        auth0_domain=AUTH0_AUTH_DOMAIN,
        claims_list=custom_claims
    )

    role_choices = []
    role_choices.append(tuple(['None', 'None']))

    for r in role_id_list:
        role_choices.append(tuple([role_id_list[r], r]))


    logging.debug('[+] Role choices: {}'.format(role_choices))

    form = CreateInviteForm(role_list=role_choices)

    if request.method == 'POST':

        logging.debug('[+] Invite form has been posted')

        if form.validate_on_submit():

            logging.debug('[+] Invite form has been validated')

            if 'email' in session[USER_PROFILE_KEY]:
                data['inviter'] = {'name' : session[USER_PROFILE_KEY]['email']}
            else:
                ##
                ## TODO: fix this
                ##
                data['inviter'] = {'name' : 'foo'}

            email = form.email.data
            role_select = form.roles.data

            logging.debug('[+] Creating invite for: {} -- {}'.format(email, role_select))


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

            try:

                if role_select == 'None':
                    member_role = '{}-{}-{}-OrgMember'.format(PROJECT_NAME, ENVIRONMENT_NAME, SYSTEM_NUMBER)
                    role_id = role_id_list[member_role]
                    data['roles'] = [role_id]
                else:
                    data['roles'] = [role_select]

            except Exception as e:
                logging.debug('[+] Error selecting role: {}'.format(e))


            logging.debug('[+] Org ID: {}'.format(org_id))
            logging.debug('[+] Invite Data: {}'.format(data))

            invite = auth0_mgmt.create_org_invite(org_id=org_id, data=data)

            data['invite_data'] = invite

            return render_template('dash/invite.html', data=data)

        else:

            title_message = 'Form did not validate'
            data = {
                'title_message' : title_message,
                'form_errors' : form.errors
            }

            logging.debug('[+] Invite form did not validate: {}'.format(form.errors))
            logging.debug('[+] Roles data: {}'.format(form.roles.data))
            logging.debug('[+] Roles data type: {}'.format(type(form.roles.data)))

            return render_template('dash/invite.html', data=data)

    else:

        form.roles.choices = role_choices
        form.roles.default = role_choices[0]
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
    return render_template( 'home/support.html')


##############################################################################
##############################################################################
##
## main
##
##############################################################################
##############################################################################


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 5000))
