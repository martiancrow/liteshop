import time
import uuid
import base64
import struct
from datetime import datetime, timedelta
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request, after_this_request
from flask_login import UserMixin, AnonymousUserMixin, login_user
from sqlalchemy.dialects.mysql import VARBINARY
from .. import db, login_manager
from sqlalchemy.sql import func
from .shop_models import shop_user
from .utility_models import utility_uuid_seed

COOKIE_NAME = 'remember_token'
AUTH_HEADER_NAME = 'Authorization'
COOKIE_DURATION = timedelta(days=365)
COOKIE_SECURE = None
COOKIE_HTTPONLY = False

class SystemRole:
    CLIENT = 0x02
    #SHOP = 0x04
    MANAGER = 0x06
    ADMIN = 0x10

class ua_user(db.Model):
    __tablename__ = 'ua_users'
    ua_user_id = db.Column(db.Integer, primary_key=True)
    ua_user_uuid = db.Column(db.String(128), unique=True, index=True)
    ua_user_system_role = db.Column(db.Integer, default=SystemRole.CLIENT)
    ua_user_email = db.Column(db.String(128), unique=True, index=True)
    ua_user_moblie = db.Column(db.String(64), unique=True, index=True)
    ua_user_nick = db.Column(db.String(64))
    ua_user_headimg = db.Column(db.String(256))
    ua_pwd_hash = db.Column(db.String(128))
    ua_email_confirmed = db.Column(db.Boolean, default=False)
    ua_mobile_confirmed = db.Column(db.Boolean, default=False)
    ua_user_status = db.Column(db.Integer, default=1) # 0:disable 1:enable
    ua_createtime = db.Column(db.DateTime(), default=datetime.utcnow)
    ref_ua_user_credit_detail = db.relationship('ua_user_credit_detail', backref='ua_user', lazy='dynamic', cascade="all, delete-orphan")
    ref_ua_user_account_detail = db.relationship('ua_user_account_detail', backref='ua_user', lazy='dynamic', cascade="all, delete-orphan")
    ref_shop_user = db.relationship('shop_user', backref='ua_user', lazy='dynamic', cascade="all, delete-orphan")
    ref_owned_shop_basic = db.relationship('shop_basic', backref='owned_user', lazy='dynamic', cascade="all, delete-orphan")
    
    def __init__(self, **kwargs):
        super(ua_user, self).__init__(**kwargs)

        if self.ua_user_uuid is None:

            us = utility_uuid_seed.query.first()

            if us:
                self.ua_user_uuid = str(uuid.uuid5(uuid.uuid1(), us.utility_uuid_seed_value))
                db.session.delete(us)
                db.session.commit()
            else:
                while True:
                    self.ua_user_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, str(uuid.uuid1())))
                    checkuuid = ua_user.query.filter_by(ua_user_uuid=self.ua_user_uuid).first()

                    if checkuuid == None:
                        break

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.ua_pwd_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.ua_pwd_hash, password)

    def generate_confirmation_email_token(self, expiration=7200):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.ua_user_uuid}).decode('utf-8')

    def confirm_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])

        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False

        if data.get('confirm') != self.ua_user_uuid:
            return False

        self.ua_email_confirmed = True
        db.session.add(self)
        db.session.commit()
        return True

    def generate_reset_pwd_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.ua_user_uuid}).decode('utf-8')

    @staticmethod
    def reset_password(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])

        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False

        user = ua_user.query.get(data.get('reset'))

        if user is None:
            return False

        user.password = new_password
        db.session.add(user)
        return True

    def add_system_role(self, role):
        self.ua_user_system_role |= role
        db.session.add(self)
        db.session.commit()
        return True

    def remove_system_role(self, role):
        self.ua_user_system_role ^= role
        db.session.add(self)
        db.session.commit()
        return True

    def get_dict(self):

        userdict = self.__dict__

        if "_sa_instance_state" in userdict:
            del userdict["_sa_instance_state"]

        return userdict

    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        for i in range(count):

            email = forgery_py.internet.email_address()
            mobile = forgery_py.basic.number(at_least=18908710050, at_most=18988299999)

            while True:

                checkemail = ua_user.query.filter_by(ua_user_email=email).first()

                if checkemail == None:
                    break

            while True:

                checkmobile = ua_user.query.filter_by(ua_user_moblie=mobile).first()

                if checkmobile == None:
                    break

            u = ua_user(ua_user_email=email,
                    ua_user_moblie=mobile,
                    ua_user_nick=forgery_py.internet.user_name(),
                    ua_email_confirmed=True,
                    ua_mobile_confirmed=True,
                    ua_user_headimg='/manager/getheadimage/74258971672e7e4b7c8c7a959c5a4b92',
                    ua_createtime=forgery_py.date.date(True))

            u.password = 'testpassword'

            db.session.add(u)
            db.session.commit()

    def __repr__(self):
        return '<ua_user %r>' % self.ua_user_nick

class ua_user_credit_detail(db.Model):
    __tablename__ = 'ua_users_credit_detail'
    ua_user_credit_detail_id = db.Column(db.Integer, primary_key=True)
    ua_user_uuid = db.Column(db.String(128), db.ForeignKey('ua_users.ua_user_uuid'))
    ua_user_credit_detail_log = db.Column(db.String(256))
    ua_user_credit_detail_signal = db.Column(db.Integer, default=0, index=True)
    ua_user_credit_detail_val = db.Column(db.Integer)
    ua_user_credit_detail_createtime = db.Column(db.DateTime(), default=datetime.utcnow)

    def __init__(self, **kwargs):
        super(ua_user_credit_detail, self).__init__(**kwargs)

    def get_user_credit_total(self, signal=0):

        if signal == 0:
            return db.session.query(func.sum(ua_user_credit_detail.ua_user_credit_detail_val).label('total')).filter_by(ua_user_uuid=self.ua_user_uuid).first()[0]
        else:
            return db.session.query(func.sum(ua_user_credit_detail.ua_user_credit_detail_val).label('total')).filter(ua_user_uuid=self.ua_user_uuid, ua_user_credit_detail_signal=signal).first()[0]

    def __repr__(self):
        return '<ua_user_credit_detail %r>' % self.ua_user.ua_user_nick

class ua_user_account_detail(db.Model):
    __tablename__ = 'ua_users_account_detail'
    ua_user_account_detail_id = db.Column(db.Integer, primary_key=True)
    ua_user_uuid = db.Column(db.String(128), db.ForeignKey('ua_users.ua_user_uuid'))
    ua_user_account_detail_log = db.Column(db.String(256))
    ua_user_account_detail_classify = db.Column(db.Integer, default=0, index=True)
    ua_user_account_detail_pay = db.Column(db.Integer)  #pay amount
    ua_user_account_detail_val = db.Column(db.Integer)  #truth amount
    ua_user_account_detail_createtime = db.Column(db.DateTime(), default=datetime.utcnow)

    def __init__(self, **kwargs):
        super(ua_user_account_detail, self).__init__(**kwargs)

    def get_user_account_val_total(self, classify=0):

        if classify == 0:
            return db.session.query(func.sum(get_user_account_total.ua_user_account_detail_val).label('total')).filter_by(ua_user_uuid=self.ua_user_uuid).first()[0]
        else:
            return db.session.query(func.sum(get_user_account_total.ua_user_account_detail_val).label('total')).filter(ua_user_uuid=self.ua_user_uuid, ua_user_account_detail_classify=classify).first()[0]

    def get_user_account_pay_total(self, classify=0):

        if classify == 0:
            return db.session.query(func.sum(get_user_account_total.ua_user_account_detail_pay).label('total')).filter_by(ua_user_uuid=self.ua_user_uuid).first()[0]
        else:
            return db.session.query(func.sum(get_user_account_total.ua_user_account_detail_pay).label('total')).filter(ua_user_uuid=self.ua_user_uuid, ua_user_account_detail_classify=classify).first()[0]

    def __repr__(self):
        return '<ua_user_account_detail %r>' % self.ua_user.ua_user_nick

class ua_session(db.Model):
    __tablename__ = 'ua_session_base'
    ua_sb_key = db.Column(db.String(256), primary_key=True)
    ua_sb_ip = db.Column(db.String(128))
    user_uuid = db.Column(db.String(128))
    ua_sb_exceed = db.Column(db.SmallInteger, default=7200)
    ua_sb_lastheart = db.Column(db.BigInteger, default=time.time)
    ua_sb_createtime = db.Column(db.BigInteger, default=time.time)
    ua_sd_datas = db.relationship('ua_session_data', backref='base', lazy='dynamic', cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        super(ua_session, self).__init__(**kwargs)

        if 'ua_sb_key' not in kwargs:
            key = generate_password_hash(str(time.time())).replace('pbkdf2:sha256:50000$', '')
            self.ua_sb_key = key

    @property
    def datas(self):
        sess_datas = {}
        for item in self.ua_sd_datas:
            if item.ua_sd_type == 'int':
                sess_datas[item.ua_sd_key] = struct.unpack('i', item.ua_sd_value)[0]

            elif item.ua_sd_type == 'str':
                sess_datas[item.ua_sd_key] = item.ua_sd_value.decode()

            else:
                sess_datas[item.ua_sd_key] = item.ua_sd_value

        return sess_datas

    def set_data(self, key, val):
        ud = ua_session_data.query.filter_by(ua_sb_key=self.ua_sb_key, ua_sd_key=key).first()

        val_type = 'bytes'

        if isinstance(val, int):
            val = struct.pack('i', val)
            val_type = 'int'

        elif isinstance(val, str):
            val = val.encode()
            val_type = 'str'

        if ud == None and val != None:
            ud = ua_session_data(ua_sb_key=self.ua_sb_key, ua_sd_key=key, ua_sd_value=val, ua_sd_type=val_type)
            db.session.add(ud)
            db.session.commit()

        elif ud != None and val == None:
            db.session.delete(ud)
            db.session.commit()

        elif ud != None and val != None:
            ud.ua_sd_value = val
            db.session.add(ud)
            db.session.commit()

    def is_exceed(self):
        return self.ua_sb_exceed < (int(time.time()) - self.ua_sb_lastheart)

    def __repr__(self):
        return '<ua_session %r>' % self.ua_sb_key

class ua_session_data(db.Model):
    __tablename__ = 'ua_session_data'
    ua_sb_key = db.Column(db.String(128), db.ForeignKey('ua_session_base.ua_sb_key'), primary_key=True)
    ua_sd_key = db.Column(db.String(64), primary_key=True)
    ua_sd_value = db.Column(VARBINARY(512))
    ua_sd_type = db.Column(db.String(8))


    def __init__(self, **kwargs):
        super(ua_session_data, self).__init__(**kwargs)

    def __repr__(self):
        return '<ua_session_data %r>' % self.ua_sd_key


class User(UserMixin):

    def __init__(self, sess, user_uuid, stophreat=False, **kwargs):

        if sess is None or not isinstance(sess, ua_session):
            raise AttributeError('session object must be provide and must be ua_session')

        self.id = sess.ua_sb_key
        self.sess = sess

        if user_uuid is None:
            self.user = None
        else:
            self.sess.user_uuid = user_uuid
            db.session.add(self.sess)
            db.session.commit()

            self.user = ua_user.query.filter_by(ua_user_uuid=self.sess.user_uuid).first()


        if not stophreat:
            self.sess.ua_sb_lastheart = time.time()
            db.session.add(self.sess)
            db.session.commit()
    
    @property
    def datas(self):
        return self.sess.datas

    def set_data(self, key, val):
        self.sess.set_data(key, val)

    def logout(self):
        self.user = None
        db.session.delete(self.sess)
        db.session.commit()

    def get_auth_token(self):
        return self.id

    def reset_lastseen(self):
        self.sess.ua_sb_lastheart = time.time()
        db.session.add(self.sess)
        db.session.commit()
       

class AnonymousUser(AnonymousUserMixin):

    def __init__(self, stophreat=False, **kwargs):

        key = None

        cookie_name = current_app.config.get('REMEMBER_COOKIE_NAME', COOKIE_NAME)
        header_name = current_app.config.get('AUTH_HEADER_NAME', AUTH_HEADER_NAME)

        if (key is None) and (cookie_name in request.cookies):
            key = request.cookies[cookie_name]

        if (key is None) and (header_name in request.headers):
            key = request.headers[header_name]

        if key is None:
            self.sess = ua_session(ua_sb_ip=request.remote_addr)
            self.id = self.sess.ua_sb_key
            db.session.add(self.sess)
            db.session.commit()

            @after_this_request
            def _set_cookie(response):
                # cookie settings
                cookie_name = current_app.config.get('REMEMBER_COOKIE_NAME', COOKIE_NAME)
                duration = current_app.config.get('REMEMBER_COOKIE_DURATION', COOKIE_DURATION)
                domain = current_app.config.get('REMEMBER_COOKIE_DOMAIN')
                path = current_app.config.get('REMEMBER_COOKIE_PATH', '/')
                secure = current_app.config.get('REMEMBER_COOKIE_SECURE', COOKIE_SECURE)
                httponly = current_app.config.get('REMEMBER_COOKIE_HTTPONLY', COOKIE_HTTPONLY)

                # head settings
                header_name = current_app.config.get('AUTH_HEADER_NAME', AUTH_HEADER_NAME)

                # data setting
                data = self.id
                expires = datetime.utcnow() + duration

                # actually set it
                response.headers[header_name] = data
                response.set_cookie(cookie_name,
                                    value=data,
                                    expires=expires,
                                    domain=domain,
                                    path=path,
                                    secure=secure,
                                    httponly=httponly)

                return response

        else:
            self.sess = ua_session.query.get(key)

            if self.sess == None:
                self.sess = ua_session(ua_sb_key=key, ua_sb_ip=request.remote_addr)
                db.session.add(self.sess)
                db.session.commit()

            self.id = key

        if not stophreat:
            self.sess.ua_sb_lastheart = time.time()
            db.session.add(self.sess)
            db.session.commit()

    @property
    def datas(self):
        return self.sess.datas

    def set_data(self, key, val):
        self.sess.set_data(key, val)

    def clear(self):
        db.session.delete(self.sess)
        db.session.commit()

    def get_auth_token(self):
        return self.id

    def reset_lastseen(self):
        self.sess.ua_sb_lastheart = time.time()
        db.session.add(self.sess)
        db.session.commit()


login_manager.anonymous_user = AnonymousUser

@login_manager.token_loader
def load_token(key):
    sess = ua_session.query.get(key)

    if sess:

        if sess.user_uuid is not None:

            return User(sess, sess.user_uuid)

    return None

# has cookie
@login_manager.user_loader
def load_user(key):
    sess = ua_session.query.get(key)

    if sess:

        if sess.user_uuid is not None:

            return User(sess, sess.user_uuid)

    return None

@login_manager.request_loader
def load_request(request):

    header_name = current_app.config.get('AUTH_HEADER_NAME', AUTH_HEADER_NAME)
    auth_token = request.headers.get(header_name)

    if auth_token:
        auth_token = auth_token.replace('Basic ', '', 1)
        sess = ua_session.query.get(auth_token)

        if sess:

            if not sess.is_exceed:

                if ua_user.query.get(sess.user_uuid):

                    return User(sess, sess.user_uuid)
    
    return None
