from .. import db

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False, unique=True)
    price = db.Column(db.Float, nullable=False)

    # Add new relationship with OrderProduct
    orders = db.relationship('OrderProduct', back_populates="product")


