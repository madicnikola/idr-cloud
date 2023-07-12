from flask import Flask
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'tajni-kljuc'  # Ovo treba da bude tajni ključ. Ne koristite ovu vrednost u produkciji.
    jwt = JWTManager(app)
    # configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@db:5432/postgres'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    # import models here
    from .models import user, product, category, order

    with app.app_context():
        db.create_all()  # create tables

    # import routes here
    from .routes import setup_routes
    setup_routes(app)

    return app
