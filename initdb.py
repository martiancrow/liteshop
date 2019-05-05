#!/Users/xiaolongliu/miniconda3/bin/python
# -*- coding:utf8 -*-

import os
from app import create_app, db
from app.models.ua_models import ua_user, SystemRole

app = create_app(os.getenv('FLASK_CONFIG') or 'default')


with app.app_context():

    db.metadata.create_all(db.engine)
    
    manager = ua_user.query.filter_by(ua_user_email='lxl@mv2.xyz')

    if manager is None:
        manager.ua_user_email = 'lxl@mv2.xyz'
        manager.ua_email_confirmed = True
        manager.ua_user_system_role = SystemRole.MANAGER
        manager.ua_user_nick = '物管'
        manager.password = "lxlloveme7"

        db.session.add(user)
        db.session.commit()
    


