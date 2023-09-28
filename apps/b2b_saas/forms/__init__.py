
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, RadioField
from wtforms.validators import DataRequired, Email, URL


##############################################################################
##############################################################################
##
##
##
##############################################################################
##############################################################################


class SignupForm(FlaskForm):
    organization = StringField('Organization Name', validators=[DataRequired()])
    email = StringField('Email', validators=[Email(), DataRequired()])
    submit = SubmitField('Join Us')


##############################################################################
##############################################################################
##
## SAML connection form
##
##############################################################################
##############################################################################


class CreateSAMLConnectionForm(FlaskForm):

    conn_id = StringField('Connection Identifier', validators=[DataRequired()])
    conn_name = StringField('Connection Display Name', validators=[DataRequired()])
    icon_url = StringField('Icon URL', validators=[URL()])

    '''
    ##
    ## currently designed to use separate forms for specific connection
    ## types, therefore this field is unnecessary.  If design is changed
    ## uncomment this stanza
    ##
    conn_strategy = SelectField(
        'Connection Strategy',
        [DataRequired()],
        choices=[('samlp', 'SAML')]
    )
    '''

    sign_req_digest = SelectField(
        'Sign Request Algorithm Digest',
        [DataRequired()],
        choices=[
            ('sha256', 'SHA256'),
            ('sha1', 'SHA1')
        ]
    )

    sign_req_algo = SelectField(
        'Sign Request Algorithm',
        [DataRequired()],
        choices=[
            ('rsa-sha256', 'RSA-SHA256'),
            ('rsa-sha1', 'RSA-SHA1')
        ]
    )

    assign_membership_on_login = RadioField(
        'Assign Membership on Login', 
        default=True,
        choices=[
            (True,'Yes'),
            (False,'No')
        ]
    )

    signin_url = StringField(
        'Sign In URL',
        validators=[DataRequired(), URL()]
    )

#    x509_cert = FileField('X509 Signing Cert', validators=[FileRequired()])
    x509_cert = FileField('X509 Signing Cert')

    submit = SubmitField('Create SAML Connection')


##############################################################################
##############################################################################
##
## Okta connection form
##
##############################################################################
##############################################################################

class CreateOktaConnectionForm(FlaskForm):

    conn_id = StringField('Connection Identifier', validators=[DataRequired()])
    conn_name = StringField('Connection Name', validators=[DataRequired()])
    icon_url = StringField('Icon URL', validators=[URL()])

    domain = StringField('Okta Domain', validators=[DataRequired()])
    client_id = StringField('Client ID', validators=[DataRequired()])
    client_secret = PasswordField('Client Secret', validators=[DataRequired()])

    assign_membership_on_login = RadioField(
        'Assign Membership on Login', 
        default=True,
        choices=[
            (True,'Yes'),
            (False,'No')
        ]
    )

    submit = SubmitField('Create Okta Connection')


##############################################################################
##############################################################################
##
##
##
##############################################################################
##############################################################################


class CreateInviteForm(FlaskForm):


    email = StringField('Email', validators=[Email(), DataRequired()])

    roles = SelectField(
        'Role',
#        [DataRequired()],
        coerce=str,
        validate_choice=False,
        choices=[]
    )

    submit = SubmitField('Send Invite')
