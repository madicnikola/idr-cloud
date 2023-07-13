from .. import db

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False, unique=True)
    products = db.relationship('Product', backref='category', lazy=True)
