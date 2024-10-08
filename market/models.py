from market import db, login_manager
from market import bcrypt
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    email_address = db.Column(db.String(length=50), nullable=False, unique=True)
    password_hash = db.Column(db.String(length=60), nullable=False)
    items = db.relationship('Trade', backref='owned_user', lazy=True)

    @property
    def password(self):
        return self.password

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)

    def can_get(self, item_obj):
        return self.id != item_obj.owner


class ShopInventory(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    isbn = isbn = db.Column(db.String(length=10), nullable=False, unique=True)
    name = db.Column(db.String(length=30), nullable=False, unique=True)
    description = db.Column(db.String(length=1024), nullable=False, unique=True)


class Trade(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    isbn = db.Column(db.String(length=10), nullable=False, unique=True)
    name = db.Column(db.String(length=30), nullable=False, unique=True)
    description = db.Column(db.String(length=1024), nullable=False, unique=True)
    owner = db.Column(db.Integer(), db.ForeignKey('user.id'))

    def __repr__(self):
        return f'Trade {self.name}'

    def get(self, user):
        self.owner = user.id
        db.session.commit()


class TradeHistory(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    isbn = db.Column(db.String(length=10), nullable=False, unique=True)
    name = db.Column(db.String(length=30), nullable=False, unique=True)
    traded_from = db.Column(db.String(length=30), nullable=False)
    traded_to = db.Column(db.String(length=30), nullable=False)
