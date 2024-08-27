from flask import Flask, request, jsonify,url_for,redirect,session,render_template
from pymongo import MongoClient
from flask_jwt_extended import create_access_token ,jwt_required ,create_refresh_token ,JWTManager,get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS,cross_origin
from flask_dance.contrib.google import make_google_blueprint, google
from msal import ConfidentialClientApplication
import os
from flask_session import Session
import identity
import identity.web
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
from pathlib import Path
import json
import urllib
import msal
import random
import string 
import base64
from flask_apscheduler import APScheduler
from email.message import EmailMessage
from flask_mail import Mail ,Message


app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.secret_key = os.urandom(12)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()


client = MongoClient(os.getenv('MONGODB_URL'))
db = client['chef_master_db']                   # AI_Chef_Master


# google login 
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.getenv('GOOGLE_OAUTH_CLIENT_ID')
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')


google_blueprint = make_google_blueprint(
    client_id=os.getenv('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile", "openid"]
)
app.register_blueprint(google_blueprint, url_prefix="/login")




@app.route("/")
def index():
    try:
        if not google.authorized:
            return redirect(url_for("google.login"))
        return redirect(url_for("google_callback"))
    
    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400




@app.route("/callback")
def google_callback():
    try:
        if not google.authorized:
            return jsonify({"error": "Failed to log in."}), 400
        resp = google.get("/oauth2/v1/userinfo")
        assert resp.ok, resp.text

        user_info = resp.json()
        exist_user = db.User.find_one({'email': user_info['email']}, {'first_name': 1, 'user_id': 1})

        if not exist_user:
            user_id = "User" + user_info['given_name'].upper() + "-" + str(round((datetime.now().timestamp())*1000000))
            db.User.insert_one({
                'first_name': user_info['given_name'],
                'last_name': user_info['family_name'],
                'email': user_info['email'],
                'user_id': user_id
            })
        else:
            user_id = exist_user['user_id']

        user_info['user_id'] = user_id
        token = create_access_token(identity=user_info['email'])
        user_info['access_token'] = token
        user_info_str = urllib.parse.quote(json.dumps(user_info))
        
        return redirect(f"{os.getenv('FRONTEND_URL')}/login?data={user_info_str}", code=302)
    
    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400




# Manual Authentication
@app.route('/auth/signup', methods =['POST'])
def register():
    try:
        first_name = request.json.get('first_name')
        last_name = request.json.get('last_name')
        country_code = request.json.get('country_code')
        phone = request.json.get('phone')
        email = request.json.get('email')
        password = request.json.get('password')

        if not (first_name and last_name and country_code and phone and email and password):
            return jsonify({'message': 'Missing required fields'}), 400
        if db.User.find_one({'email': email}):
            return jsonify({'message': 'User already exists'}), 400

        hashed_password = generate_password_hash(password)
        user_id = "User"+ first_name.upper() + "-" + str(round((datetime.now().timestamp())*1000000))
        db.User.insert_one({
            'first_name': first_name,
            'last_name': last_name,
            'country_code': country_code,
            'phone': phone,
            'email': email,
            'password': hashed_password,
            'user_id': user_id
        })
        
        return jsonify({'message': 'User registered successfully'}), 201
    
    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400




@app.route('/auth/login', methods=['POST'])
def loginAuth():
    try:
        email = request.json['email']
        password = request.json['password']
    
        user = db.User.find_one({'email': email})
        if not user or not check_password_hash(user['password'], password):
            return jsonify({'message': 'Invalid credentials'}), 401
        else:
            token  = create_access_token(identity= email)
        name = user['first_name']+" "+user['last_name']
        user_id = user['user_id']
        return jsonify(message = 'Login Successful', access_token = token, email = email, name = name, user_id = user_id)   
     
    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400
    



@app.route('/auth/validate-token', methods=['GET'])
@jwt_required()
def validate_token():
    try:
        current_user = get_jwt_identity()
        user = db.User.find_one({'email': current_user})
        if user:
            name = user['first_name'] + " " + user['last_name']
            user_id = user['user_id']
            return jsonify(message='Token is valid', email=current_user, name=name, user_id=user_id)
        else:
            return jsonify({'message': 'Invalid token'}), 401
        
    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400




@app.route('/auth/forgetPassword',methods =['POST'])
def forgetP():
    try:
        email = request.json.get('email')
        newPassword = request.json.get('newPassword')

        db.User.update_one({ "email": email },{"$set": { "password": generate_password_hash(newPassword) }})
        return jsonify({'message':"password updates succesfully"})
    
    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400




# To Generate New Dish
@app.route('/Homepage', methods=['POST'])
@jwt_required()
def generate_dish():
    try:
        data = request.get_json() 
        name = data.get('name')
        quantity = data.get('quantity')
        unit = data.get('unit')
        equipments = data.get('equipments')
        
        if not name or not quantity or not unit or not equipments:
            return jsonify({'message': 'All fields are required'}), 400
        
        item = {
            "created_at": datetime.utcnow(), 
            "name": name,
            "quantity": quantity,
            "unit": unit,
            "equipments": equipments
        }

        result = db.generate_dish.insert_one(item)
        if result.inserted_id:
            return jsonify({'message': 'Item created successfully', 'id': str(result.inserted_id)}), 201
        else:
            return jsonify({'message': 'Failed to create item'}), 500

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400
    
    
    
    
# To Show Dish into History 
@app.route("/history/<name>", methods=['GET'])
@jwt_required()
def history(name):
    try:
        item = db.generate_dish.find_one({"name": name}, {"_id": 0})
        item['created_at'] = item['created_at'].strftime('%Y-%m-%d %H:%M:%S') if 'created_at' in item else 'N/A'
        if item:
            return jsonify(item), 200
        else:
            return jsonify({'message': 'Item not found'}), 404
        
    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 500
    
    
 
#  ========================================================================================================================================
    
    
    

# Raj Code :
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from sklearn.exceptions import NotFittedError

class RecipeModel:
    def __init__(self):
        self.model = make_pipeline(TfidfVectorizer(), MultinomialNB())
        self.is_trained = False

    def train(self, X, y):
        self.model.fit(X, y)
        self.is_trained = True

    def generate_recipe(self, dish_name):
        if not self.is_trained:
            return None
        try:
            prediction = self.model.predict([dish_name])[0]
            if prediction in self.model.steps[-1][1].classes_:
                return prediction
            else:
                return None
        except NotFittedError:
            return None



import pandas as pd
import logging
from bson import json_util
import json

logging.basicConfig(level=logging.DEBUG)

data = {
    'dish_name': ['Pasta Carbonara', 'Chicken Curry', 'Caesar Salad', 'Beef Stir Fry'],
    'recipe': [
        'To make Pasta Carbonara, start by cooking 400g of spaghetti in salted boiling water until al dente. Meanwhile, in a large pan, fry 150g of diced pancetta or guanciale until crispy. In a bowl, whisk together 4 large eggs, 50g of grated Pecorino Romano, and 50g of grated Parmesan cheese. Season with freshly ground black pepper. Drain the pasta, reserving a cup of pasta water. Quickly toss the hot pasta with the crispy pancetta, then remove from heat and pour in the egg and cheese mixture, stirring rapidly to create a creamy sauce. If needed, add a splash of reserved pasta water to reach desired consistency. Serve immediately with extra grated cheese and black pepper on top.',
        
        'For Chicken Curry, begin by marinating 500g of diced chicken breast in a mixture of 2 tbsp yogurt, 1 tsp turmeric, and 1 tsp garam masala for 30 minutes. In a large pot, heat 2 tbsp of oil and fry 1 diced onion until golden. Add 3 minced garlic cloves and 1 tbsp grated ginger, cooking for another minute. Stir in 2 tbsp of curry powder and cook until fragrant. Add the marinated chicken and cook until sealed. Pour in 400ml of coconut milk and 200ml of chicken stock. Simmer for 20 minutes until the chicken is cooked through and the sauce has thickened. Season with salt to taste and stir in a handful of chopped cilantro. Serve hot with steamed basmati rice and naan bread.',
        
        'To prepare a classic Caesar Salad, start by making the dressing. In a bowl, whisk together 1 egg yolk, 2 minced garlic cloves, 2 tsp Dijon mustard, 2 tsp Worcestershire sauce, the juice of 1 lemon, and 1/2 tsp anchovy paste. Slowly drizzle in 1/2 cup of olive oil while whisking to emulsify. Season with salt and black pepper. For the salad, wash and chop 2 heads of romaine lettuce. Toss the lettuce with the dressing, making sure each leaf is well coated. Add 1 cup of garlic croutons and 1/2 cup of freshly grated Parmesan cheese. Toss again lightly. For the chicken, season 2 chicken breasts with salt and pepper, then grill until cooked through. Slice and place on top of the salad. Finish with extra Parmesan shavings and freshly ground black pepper.',
        
        'For a delicious Beef Stir Fry, start by slicing 500g of beef sirloin into thin strips. Marinate the beef in a mixture of 2 tbsp soy sauce, 1 tbsp oyster sauce, and 1 tsp sesame oil for 15 minutes. Heat 2 tbsp of vegetable oil in a wok over high heat. Add 2 minced garlic cloves and 1 tbsp grated ginger, stir-frying for 30 seconds. Add the marinated beef and stir-fry for 2-3 minutes until browned. Remove the beef and set aside. In the same wok, stir-fry a mix of vegetables: 1 sliced bell pepper, 1 sliced onion, 1 cup of broccoli florets, and 1 cup of snap peas. Cook for 3-4 minutes until crisp-tender. Return the beef to the wok. Mix 1/4 cup of chicken stock with 1 tbsp cornstarch and add to the wok, stirring until the sauce thickens. Season with additional soy sauce if needed. Serve hot over steamed rice, garnished with sliced green onions and sesame seeds.'
    ]
}
df = pd.DataFrame(data)

recipe_model = RecipeModel()

try:
    recipe_model.train(df['dish_name'], df['recipe'])
    app.logger.info("Model trained successfully")
except Exception as e:
    app.logger.error(f"Error training model: {str(e)}")
    

# List of sample dishes
sample_dishes = [
    {"name": "Spaghetti Carbonara", "cuisine": "Italian", "difficulty": "Medium"},
    {"name": "Chicken Tikka Masala", "cuisine": "Indian", "difficulty": "Medium"},
    {"name": "Caesar Salad", "cuisine": "American", "difficulty": "Easy"},
    {"name": "Beef Stroganoff", "cuisine": "Russian", "difficulty": "Medium"},
    {"name": "Vegetable Stir Fry", "cuisine": "Chinese", "difficulty": "Easy"},
    {"name": "Margherita Pizza", "cuisine": "Italian", "difficulty": "Medium"},
    {"name": "Sushi Rolls", "cuisine": "Japanese", "difficulty": "Hard"},
    {"name": "Pad Thai", "cuisine": "Thai", "difficulty": "Medium"},
    {"name": "Beef Tacos", "cuisine": "Mexican", "difficulty": "Easy"},
    {"name": "Ratatouille", "cuisine": "French", "difficulty": "Medium"},
    {"name": "Greek Salad", "cuisine": "Greek", "difficulty": "Easy"},
    {"name": "Beef Wellington", "cuisine": "British", "difficulty": "Hard"},
    {"name": "Kung Pao Chicken", "cuisine": "Chinese", "difficulty": "Medium"},
    {"name": "Lasagna", "cuisine": "Italian", "difficulty": "Medium"},
    {"name": "Fish and Chips", "cuisine": "British", "difficulty": "Medium"}
]

# Generate sample data
data_to_insert = []
for i in range(30):  # Generate 30 entries
    dish = random.choice(sample_dishes)
    data_to_insert.append({
        "name": dish["name"],
        "date": datetime.now() - timedelta(days=i),
        "cuisine": dish["cuisine"],
        "difficulty": dish["difficulty"],
        "rating": random.randint(1, 5),
        "cooking_time": random.randint(15, 120)  # in minutes
    })

# Insert data into MongoDB
result = db.dishes.insert_many(data_to_insert)

print(f"Inserted {len(result.inserted_ids)} documents into the dishes collection.")

# Verify the insertion by printing a few entries
print("\nSample entries:")
for dish in db.dishes.find().limit(5):
    print(f"{dish['name']} - {dish['date'].strftime('%Y-%m-%d')} - {dish['cuisine']} - {dish['difficulty']}")





if __name__ == '__main__':
    app.debug = True
    app.run()