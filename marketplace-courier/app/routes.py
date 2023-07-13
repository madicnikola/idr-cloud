from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt

from . import db
from .models.order import Order


def setup_routes(app):
    @app.route('/')
    def home():
        return 'Welcome to the Shop Management System!'

    @app.route('/orders_to_deliver', methods=['GET'])
    @jwt_required()
    def get_orders_to_deliver():
        try:
            claims = get_jwt()
            if claims['role'] != 'courier':
                return jsonify({"message": "Only couriers can view pending orders."}), 400

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
                return jsonify({"message": "Invalid order id. Must be number"}), 400

            order = Order.query.get(order_id)
            if not order or order.status != 'CREATED':
                return jsonify({"message": f"Invalid order status #{order.status}"}), 400

            claims = get_jwt()
            if claims['role'] != 'courier':
                return jsonify({"message": "Only couriers can pick up orders."}), 400

            order.status = 'PENDING'
            order.courier_id = claims['email']  # Assuming courier_id is the courier's email
            db.session.commit()

            return '', 200
        except KeyError:
            return jsonify({"message": "Missing order id."}), 400
        except Exception as e:
            print(str(e))  # Ispisivanje greške u konzolu
            return jsonify({'msg': 'An error occurred while processing your request: ' + str(e)}), 500
