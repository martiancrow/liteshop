from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models.ua_models import ua_user

class LoginForm(FlaskForm):
    email = StringField('', validators=[DataRequired(), Length(1, 128), Email()])
    password = PasswordField('', validators=[DataRequired()])
    submit = SubmitField('登录')


