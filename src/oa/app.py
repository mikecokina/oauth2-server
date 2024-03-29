import os

from flask import Flask
from oa.models import db
from oa.oauth2 import config_oauth
from oa.routes import bp

os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'


def create_app(config=None):
    app = Flask(__name__)

    # load default configuration
    app.config.from_object('oa.settings')

    # load environment configuration
    if 'WEBSITE_CONF' in os.environ:
        app.config.from_envvar('WEBSITE_CONF')

    # load app specified configuration
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith('.py'):
            app.config.from_pyfile(config)

    setup_app(app)
    return app


def setup_app(app):
    # Create tables if they do not exist already
    @app.before_first_request
    def create_tables():
        db.create_all()

    db.init_app(app)
    config_oauth(app)
    app.register_blueprint(bp, url_prefix='')
