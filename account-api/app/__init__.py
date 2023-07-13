import os

from flask import Flask
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    jwt = JWTManager(app)
    # configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.getenv('DB_USERNAME')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    # import models here
    from .models import user

    with app.app_context():
        db.create_all()  # create tables
        create_user()

    # import routes here
    from .routes import setup_routes
    setup_routes(app)

    return app


def create_user():
    user_data = {
        "forename": "Scrooge",
        "surname": "McDuck",
        "email": "onlymoney@gmail.com",
        "password": "evenmoremoney"
    }

    existing_user = User.query.filter_by(email=user_data['email']).first()
    if existing_user:
        print("User already exists.")
        return

    usr = User(**user_data)
    db.session.add(usr)
    db.session.commit()

    print("User added successfully.")