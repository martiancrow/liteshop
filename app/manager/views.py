import os
import time
import hashlib
from sqlalchemy import and_, or_
from functools import wraps
from datetime import datetime, timedelta
from flask import jsonify, render_template, redirect, url_for, abort, flash, request, current_app, make_response, Response
from flask_login import login_user, logout_user, login_required, current_user
from flask_moment import Moment
from . import manager
from .forms import LoginForm, UserSettingForm, PasswordSettingForm
from .. import db
from ..models.ua_models import ua_user, User, SystemRole

def manager_required(f):

    @wraps(f)
    def decorated_required(*args, **kargs):

        if current_user.is_authenticated and current_user.user.ua_user_system_role == SystemRole.MANAGER:

            return f(*args, **kargs)

        return redirect(url_for('manager.login'))

    return decorated_required


@manager.before_app_request
def before_request():
    current_user

@manager.route('/', methods=['GET'])
@manager_required
def index():

    headimgurl = url_for('static', filename='images/manager_blank_headimg.jpg')

    if current_user.user.ua_user_headimg and current_user.user.ua_user_headimg != '':
        headimgurl = current_user.user.ua_user_headimg

    return render_template('manager/index.html', headimgurl=headimgurl)

@manager.route('/usermanager', methods=['GET'])
@manager_required
def usermanager():

    headimgurl = url_for('static', filename='images/manager_blank_headimg.jpg')
    
    if current_user.user.ua_user_headimg and current_user.user.ua_user_headimg != '':
        headimgurl = current_user.user.ua_user_headimg

    return render_template('manager/usermanager.html', headimgurl=headimgurl)

@manager.route('/usersetting', methods=['GET', 'POST'])
@manager_required
def usersetting():

    form = UserSettingForm()

    if form.validate_on_submit():

        user = current_user.user
        user.ua_user_email = form.email.data
        user.ua_user_moblie = form.mobile.data
        user.ua_user_nick = form.nick.data

        db.session.add(user)
        db.session.commit()

        flash('更新成功')

    headimgurl = url_for('static', filename='images/manager_blank_headimg.jpg')
    
    if current_user.user.ua_user_headimg and current_user.user.ua_user_headimg != '':
        headimgurl = current_user.user.ua_user_headimg

    return render_template('manager/usersetting.html', headimgurl=headimgurl, form=form)

@manager.route('/passwordsetting', methods=['GET', 'POST'])
@manager_required
def passwordsetting():

    form = PasswordSettingForm()

    if form.validate_on_submit():

        user = current_user.user
        
        if user is not None and user.verify_password(form.password.data):

            if form.new_password.data == form.rep_new_password.data:

                user.password = form.new_password.data
                db.session.add(user)
                db.session.commit()

                flash('更新成功')
            else:
                flash('密码不一致')
        else:
            flash('密码错误')

    headimgurl = url_for('static', filename='images/manager_blank_headimg.jpg')
    
    if current_user.user.ua_user_headimg and current_user.user.ua_user_headimg != '':
        headimgurl = current_user.user.ua_user_headimg

    return render_template('manager/passwordsetting.html', headimgurl=headimgurl, form=form)


@manager.route('/login', methods=['GET', 'POST'])
def login():

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

    return render_template('manager/login.html', form=form)


@manager.route('/logout')
@manager_required
def logout():

    current_user.logout()
    logout_user()
    current_user.clear()

    flash('注销成功')
    return redirect(url_for('manager.login'))

@manager.route('/uploadheadimage', methods=['POST'])
@manager_required
def uploadheadimg():

    t = time.time()
    t = str(int(t))

    filename = current_user.user.ua_user_uuid + '_' + t

    hl = hashlib.md5()
    hl.update(filename.encode(encoding='utf-8'))
    filename = hl.hexdigest()

    
    with open(os.path.join(current_app.root_path, 'mediafile', 'headimage', filename + ".png"), 'wb') as fp:
        fp.write(request.data)

    user = current_user.user
    user.ua_user_headimg = url_for('manager.getheadimage', filename=filename)

    db.session.add(user)
    db.session.commit()
    

    result = {
        'code': 200,
        'url': url_for('manager.getheadimage', filename=filename)
    }

    return jsonify(result)

@manager.route('/getuser', methods=['GET', 'POST'])
def getuser():


    limit = int(request.form['limit']) if 'limit' in request.form.keys() else 10
    start = int(request.form['start']) if 'start' in request.form.keys() else 0
    page = int(request.form['page']) if 'page' in request.form.keys() else 1
    draw = int(request.form['draw']) if 'draw' in request.form.keys() else 1
    keyword = request.form['keyword'] if 'keyword' in request.form.keys() else None

    users = ua_user.query

    if keyword:
        rule = or_(ua_user.ua_user_nick.like(f'%{keyword}%'), ua_user.ua_user_email.like(f'%{keyword}%'), ua_user.ua_user_moblie.like(f'%{keyword}%'))
        users = users.filter(rule)
        print(users)

    total = users.count()
    users = users.order_by(ua_user.ua_createtime.desc()).limit(limit).offset(start).all()
    userlist = []

    for item in users:
        data = {
            'nick': item.ua_user_nick,
            'moblie': item.ua_user_moblie,
            'email': item.ua_user_email,
            'status': '启用' if item.ua_user_status else '禁用',
            'createtime': item.ua_createtime.strftime('%Y-%m-%d %H:%M'),
        }
        userlist.append(data)


    result = {
        'code': 200,
        'draw': draw,
        'total': total,
        'data': userlist
    }

    

    return jsonify(result)

@manager.route('/getheadimage/<string:filename>', methods=['GET'])
def getheadimage(filename):

    with open(os.path.join(current_app.root_path, 'mediafile', 'headimage', filename + ".png"), 'rb') as fp:
        data = fp.read()

    response = make_response(data)
    response.mimetype = "image/png"

    return response

