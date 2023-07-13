from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request, \
    get_jwt

from app import db
from app.models.category import Category
from app.models.order import Order
from app.models.orderProduct import OrderProduct
from app.models.product import Product
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

    @app.route('/categories', methods=['GET'])
    @active_session_required
    def get_categories():
        categories = Category.query.all()
        return jsonify([category.name for category in categories]), 200

    @app.route('/search', methods=['GET'])
    @jwt_required()
    def search_products():
        try:
            # Get search parameters
            product_name = request.args.get('name', '')
            category_name = request.args.get('category', '')

            # Find all products that match search criteria
            products = Product.query.filter(Product.name.like(f'%{product_name}%')).all()

            categories = set()
            products_list = []

            for product in products:
                product_categories = [category for category in product.categories if
                                      category_name.lower() in category.name.lower()]

                # Add categories to set
                categories.update([category.name for category in product_categories])

                # Add product to list if it belongs to at least one category
                if product_categories:
                    products_list.append({
                        'categories': [category.name for category in product_categories],
                        'id': product.id,
                        'name': product.name,
                        'price': product.price
                    })

            return jsonify({'categories': list(categories), 'products': products_list}), 200
        except Exception as e:
            print(str(e))  # Print the error for debugging
            return jsonify({'msg': 'An error occurred while processing your request: ' + str(e)}), 500

    @app.route('/order', methods=['POST'])
    @jwt_required()
    def order_products():
        try:
            data = request.get_json()
            customer_id = get_jwt_identity()

            if 'requests' not in data:
                return jsonify({'message': 'Field requests is missing.'}), 400

            requests = data['requests']
            order = Order(user_id=customer_id, status='CREATED', total_price=0)

            db.session.add(order)
            db.session.flush()

            for i, req in enumerate(requests):
                if 'id' not in req or 'quantity' not in req:
                    return jsonify({'message': f'Request number {i} is missing id or quantity.'}), 400

                product = Product.query.get(req['id'])
                if product is None:
                    return jsonify({'message': f'Invalid product for request number {i}.'}), 400

                order.total_price += product.price * req['quantity']

                order_product = OrderProduct(order_id=order.id, product_id=req['id'], quantity=req['quantity'])
                db.session.add(order_product)

            db.session.commit()

            return jsonify({'id': order.id}), 200

        except Exception as e:
            return jsonify({'msg': 'Missing Authorization Header', 'error': str(e)}), 401

    @app.route('/status', methods=['GET'])
    @jwt_required()
    def get_orders():
        try:
            customer_id = get_jwt_identity()
            orders = Order.query.filter_by(user_id=customer_id).all()

            orders_list = []
            for order in orders:
                order_dict = {
                    'price': order.total_price,
                    'status': order.status,
                    'timestamp': order.creation_timestamp.isoformat(),
                    'products': [{
                        'categories': [category.name for category in order_product.product.categories],
                        'id': order_product.product.id,
                        'name': order_product.product.name,
                        'price': order_product.product.price,
                        'quantity': order_product.quantity
                    } for order_product in order.products]
                }
                orders_list.append(order_dict)

            return jsonify({'orders': orders_list}), 200

        except Exception as e:
            return jsonify({'msg': 'An error occurred while processing your request: ' + str(e)}), 401

    @app.route('/delivered', methods=['POST'])
    @jwt_required()
    def confirm_delivery():
        try:
            data = request.get_json()
            order_id = data.get('id')

            if order_id is None:
                return jsonify({"message": "Missing order id."}), 400

            if not isinstance(order_id, int) or order_id <= 0:
                return jsonify({"message": "Invalid order id."}), 400

            customer_id = get_jwt_identity()
            order = Order.query.filter_by(id=order_id, user_id=customer_id, status='PENDING').first()

            if order is None:
                return jsonify({"message": "Invalid order id."}), 400

            order.status = 'COMPLETE'
            db.session.commit()

            return '', 200
        except Exception as e:
            return jsonify({"message": "An error occurred.", "error": str(e)}), 500
