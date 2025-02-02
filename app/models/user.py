from sqlalchemy import Column, Integer, String

from app.models.base import Base
from app.util.hash import (
    random_salt,
    hash_pbkdf2,
)

class User(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True)
    password = Column(String)
    coins = Column(Integer)
    salt = Column(String)

    def get_coins(self):
        return self.coins

    def credit_coins(self, i):
        self.coins += i

    def debit_coins(self, i):
        self.coins -= i

def create_user(db, username, password):
    #generate salt
    gen_salt = random_salt()
    
    #hash password
    salted_password = hash_pbkdf2(password, gen_salt)

    user = User(
        username=username,
        password=salted_password,
        coins=100,
        salt=gen_salt,
    )
    db.add(user)
    return user

def get_user(db, username):
    return db.query(User).filter_by(username=username).first()


