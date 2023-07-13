import csv
from datetime import timedelta, datetime
import re
import io

import jwt
from flask import jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, decode_token
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from app.models.category import Category
from app.models.order import Order
from app.models.product import Product
from app.models.user import User
from flask import current_app as app

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
        token = None

        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(' ')[1]
            except IndexError:
                pass

        if not token:
            return jsonify({'msg': 'Missing Authorization Header'}), 401

        try:
            # data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            data = decode_token(token)
            current_user_id = get_jwt_identity()  # This will give you identity(i.e., user_id) you set while creating access token
            current_user = User.query.filter_by(id=current_user_id).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

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
        if len(data['forename']) > 256 or len(data['surname']) > 256 or len(data['email']) > 256 or len(data['password']) > 256:
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

    @app.route('/categories', methods=['GET'])
    @active_session_required
    def get_categories():
        categories = Category.query.all()
        return jsonify([category.name for category in categories]), 200

    # dodavanje proizvoda
    @app.route('/update', methods=['POST'])
    def add_product():
        if 'Authorization' not in request.headers or request.headers['Authorization'] != "Bearer <ACCESS_TOKEN>":
            return jsonify({"msg": "Missing Authorization Header"}), 401
        if 'file' not in request.files:
            return jsonify({"message": "Field file missing."}), 400
        csv_file = request.files['file']
        data = csv_file.read().decode('utf-8')
        reader = csv.reader(io.StringIO(data))
        for i, row in enumerate(reader):
            if len(row) != 3:
                return jsonify({"message": f"Incorrect number of values on line {i}."}), 400
            categories, name, price = row
            if not price.isnumeric() or float(price) <= 0:
                return jsonify({"message": f"Incorrect price on line {i}."}), 400
            product = Product.query.filter_by(name=name).first()
            if product is not None:
                return jsonify({"message": f"Product {name} already exists."}), 400
            product = Product(categories=categories, name=name, price=price)
            db.session.add(product)
        db.session.commit()
        return '', 200

    @app.route('/product_statistics', methods=['GET'])
    def product_statistics():
        if 'Authorization' not in request.headers or request.headers['Authorization'] != "Bearer <ACCESS_TOKEN>":
            return jsonify({"msg": "Missing Authorization Header"}), 401

        statistics = []
        products = Product.query.all()
        for product in products:
            orders_with_product = [order for order in Order.query.all() if product in order.products]
            sold = sum(1 for order in orders_with_product if order.status == 'delivered')
            waiting = sum(1 for order in orders_with_product if order.status == 'pending')
            if sold > 0 or waiting > 0:
                statistics.append({
                    "name": product.name,
                    "sold": sold,
                    "waiting": waiting
                })

        return jsonify({"statistics": statistics}), 200

    # Category endpoint
    @app.route('/category_statistics', methods=['GET'])
    @jwt_required()
    def category_statistics():
        try:
            # Dohvati sve kategorije iz baze
            categories = Category.query.all()

            # Inicijalizacija liste kategorija
            statistics = []

            # Prolazak kroz sve kategorije
            for category in categories:
                # Izračunavanje broja dostavljenih proizvoda za svaku kategoriju
                delivered_products_count = sum(
                    [1 for product in category.products if product.orders.filter_by(status='delivered').count() > 0])
                statistics.append((category.name, delivered_products_count))

            # Sortiranje liste kategorija opadajuće po broju dostavljenih proizvoda i rastuće po imenu
            statistics.sort(key=lambda x: (-x[1], x[0]))

            # Izvlačenje imena kategorija iz liste
            statistics = [item[0] for item in statistics]

            return jsonify({'statistics': statistics}), 200
        except:
            return jsonify({'msg': 'Missing Authorization Header'}), 401

    # Product search endpoint
    @app.route('/search', methods=['GET'])
    @jwt_required()
    def search_products():
        try:
            # Dohvatanje parametara za pretragu
            product_name = request.args.get('name', '')
            category_name = request.args.get('category', '')

            # Dohvatanje proizvoda koji odgovaraju kriterijumima pretrage
            products = Product.query.filter(Product.name.like(f'%{product_name}%')).all()

            # Inicijalizacija liste kategorija i proizvoda
            categories = set()
            products_list = []

            # Prolazak kroz sve proizvode
            for product in products:
                # Dohvatanje kategorija koje odgovaraju kriterijumima pretrage i koje pripadaju trenutnom proizvodu
                product_categories = [category.name for category in product.categories if
                                      category.name.lower().contains(category_name.lower())]

                # Dodavanje kategorija u set kategorija
                categories.update(product_categories)

                # Dodavanje proizvoda u listu proizvoda ako pripada makar jednoj kategoriji
                if product_categories:
                    products_list.append({
                        'categories': product_categories,
                        'id': product.id,
                        'name': product.name,
                        'price': product.price
                    })

            return jsonify({'categories': list(categories), 'products': products_list}), 200
        except:
            return jsonify({'msg': 'Missing Authorization Header'}), 401

    @app.route('/order', methods=['POST'])
    @jwt_required()
    def order_products():
        try:
            data = request.get_json
            customer_id = get_jwt_identity()

            if 'requests' not in data:
                return jsonify({'message': 'Field requests is missing.'}), 400

            requests = data['requests']
            for i, req in enumerate(requests):
                if 'id' not in req:
                    return jsonify({'message': f'Product id is missing for request number {i}.'}), 400
                if 'quantity' not in req:
                    return jsonify({'message': f'Product quantity is missing for request number {i}.'}), 400
                if not isinstance(req['id'], int) or req['id'] <= 0:
                    return jsonify({'message': f'Invalid product id for request number {i}.'}), 400
                if not isinstance(req['quantity'], int) or req['quantity'] <= 0:
                    return jsonify({'message': f'Invalid product quantity for request number {i}.'}), 400

                product = Product.query.get(req['id'])
                if product is None:
                    return jsonify({'message': f'Invalid product for request number {i}.'}), 400

            order = Order(customer_id=customer_id, status='CREATED', timestamp=datetime.utcnow())
            db.session.add(order)
            for req in requests:
                product = Product.query.get(req['id'])
                order.products.append(product)
                # You should also decrease the stock quantity for the product in a real application

            db.session.commit()
            return jsonify({'id': order.id}), 200

        except:
            return jsonify({'msg': 'Missing Authorization Header'}), 401

    @app.route('/status', methods=['GET'])
    @jwt_required()
    def get_orders():
        try:
            customer_id = get_jwt_identity()
            orders = Order.query.filter_by(customer_id=customer_id).all()

            orders_list = []
            for order in orders:
                order_dict = {
                    'price': sum([product.price for product in order.products]),
                    'status': order.status,
                    'timestamp': order.timestamp.isoformat(),
                    'products': [{
                        'categories': [category.name for category in product.categories],
                        'id': product.id,
                        'name': product.name,
                        'price': product.price,
                        'quantity': 1  # You need to store the quantity in the order in a real application
                    } for product in order.products]
                }
                orders_list.append(order_dict)

            return jsonify({'orders': orders_list}), 200

        except:
            return jsonify({'msg': 'Missing Authorization Header'}), 401

    @app.route('/delivered', methods=['POST'])
    @jwt_required()
    def confirm_delivery():
        try:
            data = request.json
            order_id = data['id']

            if not isinstance(order_id, int) or order_id <= 0:
                return jsonify({"message": "Invalid order id."}), 400

            order = Order.query.get(order_id)
            if not order or order.status != 'PENDING':
                return jsonify({"message": "Invalid order id."}), 400

            order.status = 'COMPLETE'
            db.session.commit()

            return '', 200
        except KeyError:
            return jsonify({"message": "Missing order id."}), 400
        except:
            return jsonify({"message": "An error occurred."}), 500

    @app.route('/orders_to_deliver', methods=['GET'])
    @jwt_required()
    def get_orders_to_deliver():
        try:
            orders_to_deliver = Order.query.filter_by(status='PENDING').all()
            orders_to_deliver = [{"id": order.id, "email": order.customer.email} for order in orders_to_deliver]

            return jsonify({"orders": orders_to_deliver}), 200
        except:
            return jsonify({"message": "An error occurred."}), 500

    @app.route('/pick_up_order', methods=['POST'])
    @jwt_required()
    def pick_up_order():
        try:
            data = request.json
            order_id = data['id']

            if not isinstance(order_id, int) or order_id <= 0:
                return jsonify({"message": "Invalid order id."}), 400

            order = Order.query.get(order_id)
            if not order or order.status != 'PENDING':
                return jsonify({"message": "Invalid order id."}), 400

            courier_id = get_jwt_identity()
            courier = User.query.get(courier_id)
            if not courier or courier.role != 'COURIER':
                return jsonify({"message": "Only couriers can pick up orders."}), 400

            order.status = 'IN TRANSIT'
            order.courier_id = courier.id
            db.session.commit()

            return '', 200
        except KeyError:
            return jsonify({"message": "Missing order id."}), 400
        except:
            return jsonify({"message": "An error occurred."}), 500
