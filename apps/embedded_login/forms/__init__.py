
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, URL, InputRequired, Length, EqualTo, Optional





##############################################################################
##############################################################################
##
## Embedded Signup
##
##############################################################################
##############################################################################


class SignupForm(FlaskForm):
    username = StringField(
        validators=[
            InputRequired(),
            Length(3, 20, message="Please provide a valid name"),
            Regexp(
                "^[A-Za-z][A-Za-z0-9_.]*$",
                0,
                "Usernames must have only letters, " "numbers, dots or underscores",
            ),
        ]
    )
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    pwd = PasswordField(validators=[InputRequired(), Length(8, 72)])
    cpwd = PasswordField(
        validators=[
            InputRequired(),
            Length(8, 72),
            EqualTo("pwd", message="Passwords must match !"),
        ]
    )

    submit = SubmitField('Submit')



##############################################################################
##############################################################################
##
## Embedded Login
##
##############################################################################
##############################################################################


class LoginForm(FlaskForm):

    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    pwd = PasswordField(validators=[InputRequired(), Length(min=8, max=72)])

    ##
    ## Placeholder labels to enable form rendering
    ##
    username = StringField(
        validators=[Optional()]
    )

    submit = SubmitField('Submit')

