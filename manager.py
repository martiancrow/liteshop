#!/Users/xiaolongliu/miniconda3/bin/python
# -*- coding:utf8 -*-

import os
import app.models.ua_models
import app.models.goods_models
import app.models.shop_models
import app.models.store_models
from app import create_app, db
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
manager = Manager(app)
migrate = Migrate(app, db)
manager.add_command("db", MigrateCommand)

@app.shell_context_processor
def make_shell_context():
	return dict(db=db)

manager.add_command("shell", Shell(make_context=make_shell_context))

@manager.command
def test():
	"""Run the unit tests."""
	import unittest
	tests = unittest.TestLoader().discover('tests')
	unittest.TextTestRunner(verbosity=2).run(tests)

@manager.command
def addtestdata():
	"""Auto add test data"""
	#User.generate_fake()
	res_post.generate_fake()


if __name__ == "__main__":
	manager.run()