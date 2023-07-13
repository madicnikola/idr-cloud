from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request, \
    get_jwt

from app import db
from app.models.order import Order
from app.models.user import User

# Global variable to hold all active sessions
active_sessions = {}

from functools import wraps


def validate_data(data, fields):
    for field in fields:
        if not data.get(field):
            return {'message': f'Field {field} is missing.'}, 400
    return None, None


def active_session_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Get the token from the current request
        current_token = request.headers.get('Authorization').split(" ")[1]

        # Check if the token is in active_sessions
        if current_token not in active_sessions:
            return jsonify({'message': 'No active session'}), 401

        return fn(*args, **kwargs)

    return wrapper


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

    @app.route('/orders_to_deliver', methods=['GET'])
    @jwt_required()
    def get_orders_to_deliver():
        try:
            orders_to_deliver = Order.query.filter_by(status='PENDING').all()
            orders_to_deliver = [{"id": order.id, "user_id": order.user_id} for order in orders_to_deliver]

            return jsonify({"orders": orders_to_deliver}), 200
        except Exception as e:
            return jsonify({"message": "An error occurred.", "error": str(e)}), 500

    @app.route('/pick_up_order', methods=['POST'])
    @jwt_required()
    def pick_up_order():
        try:
            data = request.json
            order_id = data.get('id')

            if not order_id:
                return jsonify({"message": "Missing order id."}), 400

            try:
                order_id = int(order_id)
            except ValueError:
                return jsonify({"message": "Invalid order id."}), 400

            order = Order.query.get(order_id)
            if not order or order.status != 'CREATED':
                return jsonify({"message": "Invalid order id."}), 400

            courier_id = get_jwt_identity()
            courier = User.query.get(courier_id)
            if not courier or courier.role != 'courier':
                return jsonify({"message": "Only couriers can pick up orders."}), 400

            order.status = 'PENDING'
            order.courier_id = courier.id
            db.session.commit()

            return '', 200
        except KeyError:
            return jsonify({"message": "Missing order id."}), 400
        except:
            return jsonify({"message": "An error occurred."}), 500
