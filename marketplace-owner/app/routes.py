import csv
import io

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from . import db
from .models.category import Category
from .models.order import Order
from .models.product import Product


def setup_routes(app):
    @app.route('/')
    def home():
        return 'Welcome to the Shop Management System!'

    # dodavanje proizvoda
    @app.route('/update', methods=['POST'])
    @jwt_required()
    def add_product():
        if 'file' not in request.files:
            return jsonify({"message": "Field file missing."}), 400

        csv_file = request.files['file']
        data = csv_file.read().decode('utf-8')
        reader = csv.reader(io.StringIO(data))

        for i, row in enumerate(reader):
            if len(row) != 3:
                return jsonify({"message": f"Incorrect number of values on line {i}."}), 400

            categories_names, name, price = row
            try:
                price = float(price)
                if price <= 0:
                    return jsonify({"message": f"Incorrect price on line {i}."}), 400
            except ValueError:
                return jsonify({"message": f"Incorrect price on line {i}."}), 400

            product = Product.query.filter_by(name=name).first()
            if product is not None:
                return jsonify({"message": f"Product {name} already exists."}), 400

            categories = []
            for category_name in categories_names.split("|"):
                category = Category.query.filter_by(name=category_name).first()
                if category is None:
                    category = Category(name=category_name)
                    db.session.add(category)
                categories.append(category)

            product = Product(name=name, price=float(price))
            product.categories.extend(categories)
            db.session.add(product)

        db.session.commit()

        return '', 200

    @app.route('/product_statistics', methods=['GET'])
    @jwt_required()
    def product_statistics():
        statistics = []
        products = Product.query.all()
        for product in products:
            orders_with_product = [order for order in Order.query.all() if product in order.products]
            sold = sum(1 for order in orders_with_product if order.status == 'COMPLETE')
            waiting = sum(1 for order in orders_with_product if order.status == 'PENDING')
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
            categories = Category.query.all()
            statistics = []
            for category in categories:
                delivered_products_count = 0
                for product in category.products:
                    for order_product in product.orders:
                        if order_product.order.status == 'COMPLETE':
                            delivered_products_count += order_product.quantity
                statistics.append((category.name, delivered_products_count))
            statistics.sort(key=lambda x: (-x[1], x[0]))
            statistics = [item[0] for item in statistics]
            return jsonify({'statistics': statistics}), 200
        except Exception as e:
            print(str(e))  # Ispisivanje greške u konzolu
            return jsonify({'msg': 'An error occurred while processing your request: ' + str(e)}), 500
