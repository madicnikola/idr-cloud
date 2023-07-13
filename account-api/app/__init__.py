import os

from flask import Flask
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv

from .db import db  # Import db from your custom db file

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    jwt = JWTManager(app)
    app.config[
        'SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.getenv('DB_USERNAME')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    with app.app_context():
        from .models import user  # Move your import here
        db.create_all()  # If you have this function

    from .routes import setup_routes  # Assuming you have this file for routes
    setup_routes(app)

    return app
