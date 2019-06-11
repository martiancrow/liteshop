import time
import uuid
import base64
import struct
import bleach
from markdown import markdown
from datetime import datetime, timedelta
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request, after_this_request
from sqlalchemy import func
from sqlalchemy.dialects.mysql import LONGBLOB, LONGTEXT
from .. import db, login_manager
from .goods_models import goods_basis

# 1 is true 0 is false
# frist 4 bit for user ADUS
# secend 4 bit for goods ADUS
# third 4 bit for order ADUS
# fourth 4 bit for reserve
class ShopPremission:
    MANAGER = 0xffff
    MANAGERUSERS = 0xf000
    MANAGERGOODS = 0x0f00
    MANAGERORDERS = 0x00f0

class shop_goods_classify(db.Model):
    __tablename__ = 'shop_goods_classify'
    shop_goods_classify_id = db.Column(db.Integer, primary_key=True)
    shop_goods_classify_uuid = db.Column(db.String(128), unique=True, index=True)
    shop_goods_classify_puuid = db.Column(db.String(128), db.ForeignKey('shop_goods_classify.shop_goods_classify_uuid'), default='')
    shop_goods_classify_name = db.Column(db.String(128))
    shop_basic_uuid = db.Column(db.String(128), db.ForeignKey('shop_basic.shop_basic_uuid'), default='')
    shop_goods_classify_createtime = db.Column(db.DateTime(), default=datetime.utcnow)
    shop_goods_children_classify = db.relationship('shop_goods_classify', lazy='dynamic', cascade="all, delete-orphan")
    ref_goods_basis = db.relationship('goods_basis', backref='shop_goods_classify', lazy='dynamic')

    def __init__(self, **kwargs):
        super(shop_goods_classify, self).__init__(**kwargs)

        if self.shop_goods_classify_uuid is None:

            while True:
                self.shop_goods_classify_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, str(uuid.uuid1())))
                checkuuid = shop_goods_classify.query.filter_by(shop_goods_classify_uuid=self.shop_goods_classify_uuid).first()

                if checkuuid == None:
                    break

class shop_user(db.Model):
    __tablename__ = 'shop_user'
    shop_user_id = db.Column(db.Integer, primary_key=True)
    shop_basic_uuid = db.Column(db.String(128), db.ForeignKey('shop_basic.shop_basic_uuid'), default='')
    ua_user_uuid = db.Column(db.String(128), db.ForeignKey('ua_users.ua_user_uuid'), default='')
    shop_user_title = db.Column(db.String(64))
    shop_user_permission = db.Column(db.Integer, default=ShopPremission.MANAGER)
    shop_user_createtime = db.Column(db.DateTime(), default=datetime.utcnow)

class shop_basic(db.Model):
    __tablename__ = 'shop_basic'
    shop_owned_user_uuid = db.Column(db.String(128), db.ForeignKey('ua_users.ua_user_uuid'), default='')
    shop_basic_id = db.Column(db.Integer, primary_key=True)
    shop_basic_uuid = db.Column(db.String(128), unique=True, index=True)
    shop_basic_type = db.Column(db.Integer, default=0)
    shop_basic_status = db.Column(db.Integer, default=0) # 0:disenbale 1:enable
    shop_basic_name = db.Column(db.String(128))
    shop_basic_logo_url = db.Column(db.String(256))
    shop_basic_mobile_head_image_url = db.Column(db.String(256))
    shop_basis_createtime = db.Column(db.DateTime(), default=datetime.utcnow)
    ref_shop_goods_classify = db.relationship('shop_goods_classify', backref='shop_basic', lazy='dynamic', cascade="all, delete-orphan")
    ref_shop_user = db.relationship('shop_user', backref='shop_basic', lazy='dynamic', cascade="all, delete-orphan")
    ref_goods_basis = db.relationship('goods_basis', backref='shop_basic', lazy='dynamic', cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        super(shop_basic, self).__init__(**kwargs)

        if self.shop_basic_uuid is None:

            while True:
                self.shop_basic_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, str(uuid.uuid1())))
                checkuuid = shop_goods_classify.query.filter_by(shop_basic_uuid=self.shop_basic_uuid).first()

                if checkuuid == None:
                    break


