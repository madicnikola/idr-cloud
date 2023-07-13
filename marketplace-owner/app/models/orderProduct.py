from .order import Order
from .product import Product
from .. import db


class OrderProduct(db.Model):
    __tablename__ = 'order_product'
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'),
                         primary_key=True)  # change 'orders.id' back to 'order.id'
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), primary_key=True)
    quantity = db.Column(db.Integer)

    order = db.relationship("Order", back_populates="products")
    product = db.relationship("Product", back_populates="orders")


Order.products = db.relationship('OrderProduct', back_populates="order")
Product.orders = db.relationship('OrderProduct', back_populates="product")
