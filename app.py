from flask import Flask, jsonify, json, request, make_response
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields, ValidationError
import uuid
import jwt
import requests
import fnmatch
import random
from datetime import datetime, timedelta
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)


app.config["SECRET_KEY"]='37c42a7ebe8aaf2f2961b5782799c3b93586202137fedf8395676930c902b63c'
app.config["SQLALCHEMY_DATABASE_URI"] = 'postgresql+psycopg2://postgres:yougothired88@postgres/test'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

db = SQLAlchemy(app)

# Database

class User(db.Model):
    rand_gen = str(uuid.uuid4())
    id = db.Column(db.Integer(), primary_key = True, nullable=False)
    username = db.Column(db.String(), nullable=False, unique=True)
    password = db.Column(db.String(), nullable=False)
    name = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), nullable=False, unique=True)
    ref_code = db.Column(db.String(), default=rand_gen)
    created_at = db.Column(db.DateTime(), nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return self.username
        
    @classmethod
    def get_all(cls):
        return cls.query.all
        
    @classmethod
    def get_by_id(cls, id):
        return cls.query.get_or_404(id)

db.create_all()
#Schema

class RegSchema(Schema):
    id = fields.Integer()
    username = fields.String(required=True)
    password = fields.String(required=True)
    name = fields.String(required=True)
    email = fields.Email(required=True)
    submit_ref = fields.String(required=True)
    ref_code = fields.String()
    
class UserSchema(Schema):
    id = fields.Integer()
    username = fields.String()
    name = fields.String()
    email = fields.Email()
    ref_code = fields.String()
    
class EditSchema(Schema):
    username = fields.String(required=True)
    name = fields.String(required=True)
    email = fields.Email(required=True)
    
class LoginSchema(Schema):
    username = fields.String(required=True)
    password = fields.String(required=True)

#Token Authentication

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'token' in request.headers:
            token = request.headers['token']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=ALGORITHM)
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)

    return decorator
  
#Route

# Check all user without view database
@app.route('/user', methods=['GET'])
def get_all_user():
    user = User.query.all()
    serializer = UserSchema(many=True)
    data = serializer.dump(user)
    return jsonify(data), 201
    
@app.route('/register', methods=['POST'])
def register():   
    data = request.get_json()
    serializer = RegSchema()
    #Validation
    try:
        reg_data = serializer.load(data)
    except ValidationError as r:
        return jsonify("info: Validation Error", r.messages)
        
    #Insert to database and verification
    try:
        hashed_password = sha256_crypt.encrypt(data.get('password'))
        reg = User(
            username = data.get('username'),
            password = hashed_password,
            name = data.get('name'),
            email = data.get('email')
        )
        db.session.add(reg)
        db.session.commit()
        serializer = UserSchema()
        data = serializer.dump(reg)
    except:
        return jsonify({"info": "username or email already exist"})    
    return jsonify(data), 201
    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    serializer = LoginSchema()
    #Validation
    try:
        reg_data = serializer.load(data)
    except ValidationError as r:
        return jsonify("info: Validation Error", r.messages)
    
    #Verify username
    if not user:  
        return jsonify({"info": "could not verify username"}), 401
        
    #Verify Password
    if sha256_crypt.verify(data.get('password'), user.password):
        data: dict= {"user_id": user.id}
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})

        encoded_jwt = jwt.encode(to_encode, app.config['SECRET_KEY'], algorithm=ALGORITHM)
        
        #token = jwt.encode({'id': user.id, 'exp' : datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'])  
        serializer = UserSchema()
        data = serializer.dump(user)
        return jsonify({'token' : encoded_jwt, 'data': data}), 201

    return jsonify({"info": "could not verify password"}), 401

    
@app.route('/edit', methods=['POST'])
@token_required
def edit(current_user):
    data = request.get_json()
    user_id = User.query.filter_by(username=current_user.username)
    
    #Validation using schema
    serializer = EditSchema()
    try:
        edited_data = serializer.load(data)
    except ValidationError as r:
        return jsonify("info: Validation Error", r.messages), 400
    #Insert to database
    try:    
        user_id.update(edited_data)
        db.session.commit()
    except:
        return jsonify({"info": "username or email already exist"})
    return jsonify(edited_data), 201
    
@app.route('/referral', methods=['POST'])
@token_required
def ref(current_user):
    data = request.get_json()
    ref_code = current_user.ref_code
    if ref_code != data['ref_code']:
        return jsonify({'message': 'referral code not match'}), 401 
    return jsonify({'message': 'referral code match'}), 201

@app.route('/search', methods=['POST'])
def find_user():
    data = request.get_json()
    #Using wildcard to search username
    tag = data['search']
    search = "%{}%".format(tag)
    list_user = User.query.filter(User.username.like(search)).all()
    
    #if user not found
    if not list_user:
        return jsonify({'message': f"Couldn't find user with keyword {tag}"}), 401
    serializer = EditSchema(many=True)
    data = serializer.dump(list_user)
    return jsonify(data), 201
    
@app.route('/hero', methods=['POST'])
def hero():
    data = request.get_json()
    
    #Using Wildcard to search Hero
    search = data['input']
    filter = f"*{search}*"
    response = requests.get(f"https://ddragon.leagueoflegends.com/cdn/6.24.1/data/en_US/champion.json")
    quote = response.json()
    hero_data = quote["data"]
    hero_list = []
    #compare search with all hero name
    for i in hero_data:
        hero_list.append(i)
    match_keyword = fnmatch.filter(hero_list, filter)
    print(match_keyword)
    #if match hero > 1, insert them on list
    # if len(match_keyword) == 1:
        # single_hero = quote["data"][match_keyword[0]]
        # return jsonify(single_hero), 201
    if len(match_keyword) == 0:
        return jsonify({'message': f"Couldn't find hero with keyword {filter}"}), 401
    random_hero = random.choice(match_keyword)
    result = quote["data"][random_hero]
    return jsonify(result), 201



@app.get("/")
def root():
    return {"message": "Test_Teknis"}
    
