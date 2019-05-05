from functools import wraps
from datetime import datetime, timedelta
from flask import jsonify, render_template, redirect, url_for, abort, flash, request, current_app, make_response
from flask_login import login_required, current_user
from flask_moment import Moment
from . import manager
from .forms import LoginForm
from .. import db
from ..models.ua_models import ua_user, User, SystemRole

def manager_required(f):

    @wraps(f)
    def decorated_required(*args, **kargs):

        if current_user.is_authenticated and current_user.user.ua_user_system_role != SystemRole.MANAGER:

            return f(*args, **kargs)

        return redirect(url_for('manager.login'))

    return decorated_required


@manager.before_app_request
def before_request():
    current_user

@manager.route('/', methods=['GET'])
@manager_required
def index():
    
    #return render_template('user/postlist.html', cid=classid)
    return 'manager index page'


@manager.route('/login', methods=['GET', 'POST'])
def login():

    '''
    
    if not current_user.is_anonymous:
        return redirect(url_for('manager.index'))

    form = LoginForm()

    if form.validate_on_submit():

        user = ua_user.query.filter_by(ua_user_email=form.email.data).first()

        if user is not None and user.verify_password(form.password.data) and user.ua_user_system_role == SystemRole.MANAGER:

            lguser = User(current_user.sess, user.ua_user_uuid)
            login_user(lguser, True)

            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('manager.index')

            return redirect(next)

        flash('账号或密码错误')

    '''
    

    #return render_template('manager/login.html', form=form)
    return 'manager login page'

