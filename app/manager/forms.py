from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models.ua_models import ua_user

class LoginForm(FlaskForm):
    email = StringField('', validators=[DataRequired(), Length(1, 128), Email()])
    password = PasswordField('', validators=[DataRequired()])
    submit = SubmitField('登录')


class UserSettingForm(FlaskForm):
    email = StringField('', validators=[DataRequired(), Length(1, 128), Email()])
    mobile = StringField('', validators=[DataRequired(), Length(1, 64)])
    nick = StringField('', validators=[DataRequired(), Length(1, 64)])

class PasswordSettingForm(FlaskForm):
    password = PasswordField('', validators=[DataRequired()])
    new_password = PasswordField('', validators=[DataRequired()])
    rep_new_password = PasswordField('', validators=[DataRequired()])


