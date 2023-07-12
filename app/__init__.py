from flask import Flask
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'secret-key'  # Replace with your secret key. Do not use this value in production.
    jwt = JWTManager(app)

    # Configuration for PostgreSQL
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@db:5432/postgres'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    # Import models here
    from .models import user, product, category, order

    with app.app_context():
        db.create_all()  # Create tables

    # Import routes here
    from .routes import setup_routes
    setup_routes(app)

    return app