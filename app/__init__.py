import os
from dotenv import load_dotenv

import psycopg2
from flask import Flask
from flask_jwt_extended import JWTManager

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = f"{os.getenv('JWT_SECRET')}"  # Ovo treba da bude tajni ključ. Ne koristite ovu vrednost u produkciji.
    jwt = JWTManager(app)
    # configuration
    connection_string = f"dbname='{os.getenv('DB_NAME')}' user='{os.getenv('DB_USERNAME')}' host='{os.getenv('DB_HOST')}' password='{os.getenv('DB_PASSWORD')}' port='{os.getenv('DB_PORT')}'"

    # Establish connection to PostgresSQL
    conn = psycopg2.connect(connection_string)
    cursor = conn.cursor()

    # import models here
    from .models import user, product, category, order

    with app.app_context():
        db.create_all()  # create tables

    # import routes here
    from .routes import setup_routes
    setup_routes(app)

    return app
