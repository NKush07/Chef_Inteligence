import json
import os
import urllib
from datetime import datetime, timedelta

from bson import json_util
from flask import Flask, request, jsonify, url_for, redirect, session, flash
from flask_apscheduler import APScheduler
from flask_cors import CORS
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

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

# Mongodb 
client = MongoClient(os.getenv('MONGODB_URL'))
db = client['chef_master_db']  # AI_Chef_Master
dishes = db['dishes']


# google login configuration
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.getenv('GOOGLE_OAUTH_CLIENT_ID')
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')

google_blueprint = make_google_blueprint(
    client_id=os.getenv('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile",
           "openid"]
)
app.register_blueprint(google_blueprint, url_prefix="/login")

# Facebook login configuration
app.config["FACEBOOK_OAUTH_CLIENT_ID"] = os.getenv('FACEBOOK_OAUTH_CLIENT_ID')
app.config["FACEBOOK_OAUTH_CLIENT_SECRET"] = os.getenv('FACEBOOK_OAUTH_CLIENT_SECRET')

facebook_blueprint = make_facebook_blueprint(
    client_id=os.getenv('FACEBOOK_OAUTH_CLIENT_ID'),
    client_secret=os.getenv('FACEBOOK_OAUTH_CLIENT_SECRET'),
    redirect_to="facebook_authorized"
)
app.register_blueprint(facebook_blueprint, url_prefix="/login")

# ==============================================================================================================================================


@app.route("/")
def index():
    try:
        if not google.authorized and not facebook.authorized:
            return redirect(url_for("google.login")) 
        return redirect(url_for("google_callback"))
    
    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400


def handle_oauth_callback(user_info):
    email = user_info.get("mail") or user_info.get("userPrincipalName") or user_info.get("email")
    first_name = user_info.get("givenName") or user_info.get("first_name")
    last_name = user_info.get("surname") or user_info.get("last_name")

    if not email:
        flash("Email not available or not verified.", category="error")
        return redirect(url_for("index"))

    user = db.User.find_one({'email': email})
    if not user:
        user_id = "User" + first_name.upper() + "-" + str(round((datetime.now().timestamp()) * 1000000))
        db.User.insert_one({
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'user_id': user_id
        })
    else:
        user_id = user['user_id']

    # Create JWT token
    token = create_access_token(identity={'email': email, 'user_id': user_id})

    user_info['user_id'] = user_id
    user_info['access_token'] = token
    user_info_str = urllib.parse.quote(json.dumps(user_info))

    return redirect(f"{os.getenv('FRONTEND_URL')}/login?data={user_info_str}", code=302)


@app.route("/callback/google")
def google_callback():
    try:
        if not google.authorized:
            return jsonify({"error": "Failed to log in with Google."}), 400

        resp = google.get("/oauth2/v1/userinfo")
        assert resp.ok, resp.text

        user_info = resp.json()
        return handle_oauth_callback(user_info)

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400


@app.route("/login/facebook/authorized")
def facebook_authorized():
    try:
        if not facebook.authorized:
            return jsonify({"error": "Failed to log in with Facebook."}), 400

        resp = facebook.get("/me?fields=id,name,email")
        assert resp.ok, resp.text

        user_info = resp.json()
        return handle_oauth_callback(user_info)

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400



# Manual Authentication
@app.route('/auth/signup', methods=['POST'])
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
        user_id = "User" + first_name.upper() + "-" + str(round((datetime.now().timestamp()) * 1000000))
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
        
        token = create_access_token(identity=email)
        name = user['first_name'] + " " + user['last_name']
        user_id = user['user_id']
        session['user_id'] = user_id  # Storing user_id in session
        session['email'] = email
        return jsonify(message='Login Successful', access_token=token, email=email, name=name, user_id=user_id)

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


@app.route('/auth/forgetPassword', methods=['POST'])
def forgetP():
    try:
        email = request.json.get('email')
        newPassword = request.json.get('newPassword')

        db.User.update_one({"email": email}, {"$set": {"password": generate_password_hash(newPassword)}})
        return jsonify({'message': "password updates succesfully"})

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400


# To Generate New Dish
@app.route('/Homepage', methods=['POST'])
@jwt_required()
def generate_dishes():
    try:
        data = request.get_json()
        items = data.get('items')
        user_id = session.get('user_id')

        if not items or not isinstance(items, list):
            return jsonify({'message': 'Items must be a list and cannot be empty'}), 400

        for item in items:
            name = item.get('name')
            quantity = item.get('quantity')
            unit = item.get('unit')
            equipments = item.get('equipments')

            if not name or not quantity or not unit or not equipments:
                return jsonify({'message': f'All fields are required for item: {name}'}), 400

            dish = {
                "created_at": datetime.utcnow(),
                "name": name,
                "quantity": quantity,
                "unit": unit,
                "equipments": equipments,
                "user_id": user_id
            }

            result = db.generate_dish.insert_one(dish)
            if not result.inserted_id:
                return jsonify({'message': f'Failed to create item: {name}'}), 500

        return jsonify({'message': 'Items created successfully'}), 201

    except Exception as e:
        return jsonify({'message': f'Something went wrong: {str(e)}'}), 400



# To Show Dish into History 
@app.route("/history/<name>", methods=['GET'])
@jwt_required()
def history(name):
    try:
        user_id = session.get('user_id')
        items = list(db.generate_dish.find({"user_id": user_id}, {"_id": 0, "user_id": 0}))
        
        for item in items:
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
from flask import Flask, request, jsonify
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
import numpy as np

# Modified data structure
data = {
    'dish_name': ['Pasta Carbonara', 'Chicken Curry', 'Caesar Salad', 'Beef Stir Fry'],
    'ingredients': [
        '400g spaghetti, 150g pancetta, 4 eggs, 50g Pecorino Romano, 50g Parmesan',
        '500g chicken breast, 2 tbsp yogurt, 1 tsp turmeric, 1 tsp garam masala, 1 onion, 3 garlic cloves, 1 tbsp ginger, 2 tbsp curry powder, 400ml coconut milk, 200ml chicken stock',
        '2 heads romaine lettuce, 1 egg yolk, 2 garlic cloves, 2 tsp Dijon mustard, 2 tsp Worcestershire sauce, 1 lemon, 1/2 tsp anchovy paste, 1/2 cup olive oil, 1 cup croutons, 1/2 cup Parmesan, 2 chicken breasts',
        '500g beef sirloin, 2 tbsp soy sauce, 1 tbsp oyster sauce, 1 tsp sesame oil, 2 tbsp vegetable oil, 2 garlic cloves, 1 tbsp ginger, 1 bell pepper, 1 onion, 1 cup broccoli, 1 cup snap peas, 1/4 cup chicken stock, 1 tbsp cornstarch'
    ],
    'steps': [
        ['Cook spaghetti in salted water', 'Fry pancetta until crispy', 'Whisk eggs and cheese',
         'Toss hot pasta with pancetta', 'Add egg mixture to create sauce', 'Serve with extra cheese and pepper'],
        ['Marinate chicken', 'Fry onion, garlic, and ginger', 'Add curry powder and chicken',
         'Pour in coconut milk and stock', 'Simmer until cooked', 'Serve with rice and naan'],
        ['Make dressing', 'Prepare lettuce and croutons', 'Grill and slice chicken', 'Toss salad with dressing',
         'Add chicken and extra cheese'],
        ['Marinate beef', 'Stir-fry garlic and ginger', 'Cook beef', 'Stir-fry vegetables',
         'Combine beef and vegetables', 'Thicken sauce', 'Serve over rice']
    ],
    'video_link': [
        'https://www.youtube.com/watch?v=GDUbWNJLPnc',
        'https://www.youtube.com/watch?v=GDUbWNJLPnc',
        'https://www.youtube.com/watch?v=GDUbWNJLPnc',
        'https://www.youtube.com/watch?v=GDUbWNJLPnc'
    ]
}

#C:/Users/ZEN/Desktop/Web-Dish/frontend/src/components/SecondaryIntelligence/data/videos/dough.mp4

df = pd.DataFrame(data)


class RecipeModel:
    def __init__(self):
        self.vectorizer = TfidfVectorizer()
        self.tfidf_matrix = None
        self.is_trained = False

    def train(self, dish_names):
        self.tfidf_matrix = self.vectorizer.fit_transform(dish_names)
        self.is_trained = True

    def find_closest_recipe(self, query):
        if not self.is_trained:
            return None
        query_vec = self.vectorizer.transform([query])
        similarities = cosine_similarity(query_vec, self.tfidf_matrix).flatten()
        closest_index = np.argmax(similarities)
        return closest_index


recipe_model = RecipeModel()
recipe_model.train(df['dish_name'])

#CHAT-GPT ROUTE
@app.route('/generate_recipe', methods=['POST'])
def generate_recipe():
    try:
        data = request.json
        dish_name = data.get('dish')
        if not dish_name:
            return jsonify({'error': 'No dish name provided'}), 400

        closest_index = recipe_model.find_closest_recipe(dish_name)
        if closest_index is None:
            return jsonify({'error': 'Model not trained'}), 500

        recipe = {
            'dish_name': df.loc[closest_index, 'dish_name'],
            'ingredients': df.loc[closest_index, 'ingredients'],
            'steps': df.loc[closest_index, 'steps'],
            'video_link': df.loc[closest_index, 'video_link']
        }
        return jsonify(recipe)
    except Exception as e:
        app.logger.error(f"Error generating recipe: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


# sidebar history
@app.route('/api/dish_history', methods=['GET', 'POST'])
def get_dish_history():
    try:
        # Test database connection
        if db.command('ping'):
            print("Pinged your deployment. You successfully connected to MongoDB!")
        else:
            return jsonify({"error": "Failed to connect to MongoDB"}), 500

        dishes_cursor = dishes.find().sort("date", -1).limit(5)
        dishes_list = json.loads(json_util.dumps(dishes_cursor))

        if not dishes_list:
            print("No dishes found in the database")
            return jsonify({"dishes": []}), 200

        for dish in dishes_list:
            if 'date' in dish and '$date' in dish['date']:
                dish['date'] = dish['date']['$date'][:10]
            else:
                dish['date'] = 'Unknown'

        return jsonify({"dishes": dishes_list})
    except Exception as e:
        app.logger.error(f"An error occurred: {str(e)}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


# genrated recipes
@app.route('/start-process', methods=['POST'])
def start_process():
    try:
        data = request.json
        print(data)
        return jsonify({"message": "Process started successfully"}), 200

    except Exception as e:
        print(f"Error starting process: {str(e)}")
        return jsonify({"error": "Something went wrong"}), 500


if __name__ == '__main__':
    app.debug = True
    app.run()
