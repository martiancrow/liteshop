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
from .goods_models import goods_basis

class store_goods_classify(db.Model):
    __tablename__ = 'store_goods_classify'
    store_goods_classify_id = db.Column(db.Integer, primary_key=True)
    store_goods_classify_uuid = db.Column(db.String(128), unique=True, index=True)
    store_goods_classify_puuid = db.Column(db.String(128), db.ForeignKey('store_goods_classify.store_goods_classify_uuid'), default='')
    store_goods_classify_name = db.Column(db.String(128))
    store_goods_classify_createtime = db.Column(db.DateTime(), default=datetime.utcnow)
    store_goods_children_classify = db.relationship('store_goods_classify', lazy='dynamic', cascade="all, delete-orphan")
    ref_goods_basis = db.relationship('goods_basis', backref='store_goods_classify', lazy='dynamic')

    def __init__(self, **kwargs):
        super(ua_user, self).__init__(**kwargs)

        if self.store_goods_classify_uuid is None:

            while True:
                self.store_goods_classify_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, str(uuid.uuid1())))
                checkuuid = shop_goods_classify.query.filter_by(store_goods_classify_uuid=self.store_goods_classify_uuid).first()

                if checkuuid == None:
                    break
