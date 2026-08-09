from flask import Flask
from flask_cors import CORS

from app.config.config import Config
from app.extensions import db, bcrypt


def create_app():
    app = Flask(__name__)

    app.config.from_object(Config)

    CORS(app)

    db.init_app(app)
    bcrypt.init_app(app)

    from app.api.routes import api
    app.register_blueprint(api)

    with app.app_context():
        from app.models import User
        db.create_all()

    return app