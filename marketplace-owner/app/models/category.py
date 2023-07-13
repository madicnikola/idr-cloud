from .. import db

categories_products = db.Table('categories_products',
    db.Column('category_id', db.Integer, db.ForeignKey('category.id'), primary_key=True),
    db.Column('product_id', db.Integer, db.ForeignKey('product.id'), primary_key=True)
)
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False, unique=True)
    products = db.relationship('Product', secondary=categories_products, backref=db.backref('categories', lazy='dynamic'))


