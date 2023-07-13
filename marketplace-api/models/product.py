from .. import db

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    name = db.Column(db.String(256), nullable=False, unique=True)
    price = db.Column(db.Float, nullable=False)
