import time
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

class goods_basis_customize_attributs(db.Model):
    __tablename__ = 'goods_basis_dynamic_attributs'
    goods_basis_customize_attributs_id = db.Column(db.Integer, primary_key=True)
    goods_basis_uuid = db.Column(db.String(128), db.ForeignKey('goods_basis.goods_basis_uuid'))
    goods_basis_customize_attributs_name = db.Column(db.String(128))
    goods_basis_customize_attributs_value = db.Column(db.String(128))


class goods_basis_sales_data_classify(db.Model):
    __tablename__ = 'goods_basis_sales_data_classify'
    goods_basis_sales_data_classify_id = db.Column(db.Integer, primary_key=True)
    goods_basis_sales_data_classify_uuid = db.Column(db.String(128), unique=True, index=True)
    goods_basis_sales_data_classify_puuid = db.Column(db.String(128), db.ForeignKey('goods_basis_sales_data_classify.goods_basis_sales_data_classify_uuid'), default='')
    goods_basis_uuid = db.Column(db.String(128), db.ForeignKey('goods_basis.goods_basis_uuid'))
    goods_basis_sales_data_classify_title = db.Column(db.String(128))
    goods_basis_sales_data_classify_name = db.Column(db.String(128))
    goods_basis_sales_data_classify_remark = db.Column(db.String(128))
    goods_basis_sales_data_classify_image_url = db.Column(db.String(256), default='')
    goods_basis_sales_data_classify_price = db.Column(db.Integer, default=0) #penny
    goods_basis_sales_data_classify_stock = db.Column(db.Integer, default=0)
    goods_basis_sales_data_classify_shop_code = db.Column(db.String(128))
    goods_basis_sales_data_classify_bar_code = db.Column(db.String(128))
    goods_basis_sales_data_classify_sort = db.Column(db.Integer, default=0) #desc
    goods_basis_sales_data_children_classify = db.relationship('goods_basis_sales_data_classify', lazy='dynamic', cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        super(ua_user, self).__init__(**kwargs)

        if self.goods_basis_sales_data_classify_uuid is None:

            while True:
                self.goods_basis_sales_data_classify_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, str(uuid.uuid1())))
                checkuuid = goods_basis.query.filter_by(goods_basis_sales_data_classify_uuid=self.goods_basis_sales_data_classify_uuid).first()

                if checkuuid == None:
                    break

class goods_basis_hotimage(db.Model):
    __tablename__ = 'goods_basis_hotimage'
    goods_basis_hotimage_id = db.Column(db.Integer, primary_key=True)
    goods_basis_uuid = db.Column(db.String(128), db.ForeignKey('goods_basis.goods_basis_uuid'))
    goods_basis_hotimage_url = db.Column(db.String(256), default='')
    goods_basis_hotimage_sort = db.Column(db.Integer, default=0) #desc

class goods_basis_description_mobile_client(db.Model):
    __tablename__ = 'goods_basis_description_mobile_client'
    goods_basis_description_mobile_client_id = db.Column(db.Integer, primary_key=True)
    goods_basis_uuid = db.Column(db.String(128), db.ForeignKey('goods_basis.goods_basis_uuid'))
    goods_basis_description_mobile_client_html = db.Column(LONGTEXT)
    

class goods_basis(db.Model):
    __tablename__ = 'goods_basis'
    goods_basis_id = db.Column(db.Integer, primary_key=True)
    shop_goods_classify_uuid = db.Column(db.String(128), db.ForeignKey('shop_goods_classify.shop_goods_classify_uuid'))
    store_goods_classify_uuid = db.Column(db.String(128), db.ForeignKey('store_goods_classify.store_goods_classify_uuid'))
    shop_basic_uuid = db.Column(db.String(128), db.ForeignKey('shop_basic.shop_basic_uuid'))
    goods_basis_uuid = db.Column(db.String(128), unique=True, index=True)
    goods_basis_title = db.Column(db.String(128))
    goods_basis_type = db.Column(db.Integer, default=0)
    goods_basis_updatetime = db.Column(db.DateTime(), default=datetime.utcnow)
    goods_basis_createtime = db.Column(db.DateTime(), default=datetime.utcnow)
    ref_goods_basis_customize_attributs = db.relationship('goods_basis_customize_attributs', backref='goods_basis', lazy='dynamic', cascade="all, delete-orphan")
    ref_goods_basis_sales_data_classify = db.relationship('goods_basis_sales_data_classify', backref='goods_basis', lazy='dynamic', cascade="all, delete-orphan")
    ref_goods_basis_description_mobile_client = db.relationship('goods_basis_description_mobile_client', backref='goods_basis', lazy='dynamic', cascade="all, delete-orphan")
    ref_goods_basis_hotimage = db.relationship('goods_basis_hotimage', backref='goods_basis', lazy='dynamic', cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        super(ua_user, self).__init__(**kwargs)

        if self.goods_basis_uuid is None:

            while True:
                self.goods_basis_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, str(uuid.uuid1())))
                checkuuid = goods_basis.query.filter_by(goods_basis_uuid=self.goods_basis_uuid).first()

                if checkuuid == None:
                    break

