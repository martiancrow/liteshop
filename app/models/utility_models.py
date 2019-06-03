import time
import uuid
import base64
import struct
from datetime import datetime, timedelta
import hashlib
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request, after_this_request
from .. import db, login_manager
from sqlalchemy.sql import func

class utility_uuid_seed(db.Model):
    __tablename__ = 'utility_uuid_seeds'
    utility_uuid_seed_id = db.Column(db.Integer, primary_key=True)
    utility_uuid_seed_value = db.Column(db.String(64), unique=True, index=True)
    utility_uuid_seed_createtime = db.Column(db.DateTime(), default=datetime.utcnow)

    def __init__(self, **kwargs):
        super(utility_uuid_seed, self).__init__(**kwargs)

    @staticmethod
    def generate_data(count=100, prefix='', suffix=''):
        from random import seed, randint
        import forgery_py

        seed()
        for i in range(count):

            while True:

                value = str(forgery_py.basic.number(at_least=10000000000, at_most=19999999999))

                value = prefix + value + suffix

                checkvalue = utility_uuid_seed.query.filter_by(utility_uuid_seed_value=value).first()

                if checkvalue == None:
                    break

            s = utility_uuid_seed(utility_uuid_seed_value=value)

            db.session.add(s)
            db.session.commit()