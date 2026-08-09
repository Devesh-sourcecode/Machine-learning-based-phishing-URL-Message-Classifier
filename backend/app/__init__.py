from flask import Flask
from flask_cors import CORS

from app.config.config import Config
from app.extensions import db, bcrypt, jwt


def create_app():
    app = Flask(__name__)

    app.config.from_object(Config)

    CORS(app)

    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)

    from app.api.routes import api
    app.register_blueprint(api)

    from app.api.v1.auth import auth_bp
    app.register_blueprint(auth_bp)

    from app.api.v1.scan import scan_bp
    app.register_blueprint(scan_bp)

    with app.app_context():
        from app.models import User
        db.create_all()

    return app