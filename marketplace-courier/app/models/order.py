from datetime import datetime
from .. import db

class Order(db.Model):
    __tablename__ = 'order'  # change table name back to 'order'

    id = db.Column(db.Integer, primary_key=True)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    creation_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=False)

    # Add new relationship with OrderProduct
    products = db.relationship('OrderProduct', back_populates="order")

    # # Define relationship with User model
    # user = db.relationship('User', backref=db.backref('orders', lazy=True))

    def __repr__(self):
        return '<Order {}>'.format(self.id)
