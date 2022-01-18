
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, URL


##############################################################################
##############################################################################
##
##
##
##############################################################################
##############################################################################


class LoginForm(FlaskForm):
    organization_id = StringField('Organization ID')
    invitation_id = StringField('Invitation ID')
    connection_id = StringField('Connection ID')
    audience = StringField('Audience')
    scope = StringField('Scope')
    redirect_uri = StringField('Redirect URI')
    screen_hint = StringField('Screen Hint')
    submit = SubmitField('Submit')

