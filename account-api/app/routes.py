import re
from datetime import timedelta

from flask import jsonify, request
from flask_jwt_extended import jwt_required, verify_jwt_in_request, \
    get_jwt
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from app.models.user import User


from functools import wraps


def validate_data(data, fields):
    for field in fields:
        if not data.get(field):
            return {'message': f'Field {field} is missing.'}, 400
    return None, None



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        verify_jwt_in_request()  # This will ensure the token is valid.
        claims = get_jwt()  # If the token is valid, we can now safely use this to get the claims.
        email = claims['email']  # Getting the user email from the token.
        current_user = User.query.filter_by(email=email).first()  # Fetching user using email
        if not current_user:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)

    return decorated


def setup_routes(app):
    @app.route('/')
    def home():
        return 'Welcome to the Shop Management System!'

    from flask_jwt_extended import create_access_token

    @app.route('/register_customer', methods=['POST'])
    @app.route('/register_courier', methods=['POST'])
    def register():
        data = request.get_json()

        # provera da li su sva polja prisutna
        error, status = validate_data(data, ['forename', 'surname', 'email', 'password'])
        if error:
            return jsonify(error), status

        # Proverite dužinu svakog unosa
        if len(data['forename']) > 256 or len(data['surname']) > 256 or len(data['email']) > 256 or len(
                data['password']) > 256:
            return jsonify({"message": "All fields must be 256 characters or less"}), 400

        # provera da li je email validan
        if not re.match(r"[^@]+@[^@]+\.[^@]+", data['email']):
            return jsonify({'message': 'Invalid email.'}), 400

        # provera da li je lozinka validna
        if len(data['password']) < 8:
            return jsonify({'message': 'Invalid password.'}), 400

        # provera da li korisnik vec postoji
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already exists.'}), 400

        # kreiranje novog korisnika
        new_user = User(
            email=data['email'],
            password=generate_password_hash(data['password'], method='sha256'),
            forename=data['forename'],
            surname=data['surname'],
            role=request.path[1:].split('_')[1]  # 'customer' ili 'courier'
        )
        db.session.add(new_user)
        db.session.commit()
        return '', 200

    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()

        # provera da li su sva polja prisutna
        error, status = validate_data(data, ['email', 'password'])
        if error:
            return jsonify(error), status

        if len(data['email']) > 256 or len(data['password']) > 256:
            return jsonify({"message": "All fields must be 256 characters or less"}), 400

        # provera da li je email validan
        if not re.match(r"[^@]+@[^@]+\.[^@]+", data['email']):
            return jsonify({'message': 'Invalid email.'}), 400

        user = User.query.filter_by(email=data['email']).first()

        # provera da li korisnik postoji i da li se lozinke poklapaju
        if not user or not check_password_hash(user.password, data['password']):
            return jsonify({'message': 'Invalid credentials.'}), 400

        # generisanje tokena
        additional_claims = {"forename": user.forename, "surname": user.surname, "email": user.email, "role": user.role}
        expires = timedelta(hours=1)
        access_token = create_access_token(identity=user.id, additional_claims=additional_claims, expires_delta=expires)

        return jsonify({'accessToken': access_token}), 200

    @app.route('/delete', methods=['POST'])
    @token_required
    def delete(current_user):
        user = User.query.filter_by(id=current_user.id).first()

        if not user:
            return jsonify({'message': 'Unknown user.'}), 400

        db.session.delete(user)
        db.session.commit()

        return '', 200

    @app.route('/logout', methods=['POST'])
    @jwt_required()
    def logout():
        # Get the token from the current request
        current_token = request.headers.get('Authorization').split(" ")[1]

        # Remove the token from active_sessions
        active_sessions.pop(current_token, None)

        return jsonify({'message': 'Logged out'}), 200
