
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
##
##
##############################################################################
##############################################################################


class CreateConnectionForm(FlaskForm):

    conn_name = StringField('Connection Name', validators=[DataRequired()])

    conn_strategy = SelectField(
        'Connection Strategy',
        [DataRequired()],
        choices=[('samlp', 'SAML')]
    )

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

    submit = SubmitField('Create Connection')


##############################################################################
##############################################################################
##
##
##
##############################################################################
##############################################################################


class CreateInviteForm(FlaskForm):

    email = StringField('Email', validators=[Email(), DataRequired()])
    submit = SubmitField('Send Invite')
