from flask import Flask, request, redirect, session,url_for, jsonify, render_template
from flask_pymongo import PyMongo
import os
import razorpay
import logging
from bson import ObjectId
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restx import Api, Resource, fields, Namespace, abort
import requests
import hmac
import hashlib
from flask_cors import CORS  # Import CORS
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from google.auth import credentials
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import traceback  # Import traceback module
from datetime import datetime
import json
from authlib.integrations.flask_client import OAuth



# Load environment variables
load_dotenv()
# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')
app.permanent_session_lifetime = timedelta(days=7)



# Enable CORS
CORS(app)  # This will enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# MongoDB configurations
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/ecommerce_db')
mongo = PyMongo(app)

# Initialize Razorpay client
RAZORPAY_KEY_ID = os.getenv('RAZORPAY_KEY_ID', 'RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET', 'RAZORPAY_KEY_SECRET')
client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# JWT configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'JWT_SECRET_KEY')  # Change this!
jwt = JWTManager(app)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize Flask-RESTX
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}
api = Api(app, authorizations=authorizations, security='Bearer', version='1.0', title='E-commerce API', description='A simple e-commerce API')


# User namespace
user_ns = Namespace('users', description='User operations')

# Define models
register_model = user_ns.model('Register', {
    'first_name': fields.String(required=True, description='First name of the user'),
    'last_name': fields.String(required=True, description='Last name of the user'),
    'email': fields.String(required=True, description='Email of the user'),
    'password': fields.String(required=True, description='Password of the user')
})

#Discount model

discount_code_model = api.model('DiscountCode', {
    'code': fields.String(required=True, description='Discount Code')
})


login_model = user_ns.model('Login', {
    'email': fields.String(required=True, description='Email of the user'),
    'password': fields.String(required=True, description='Password of the user')
})

account_details_model = user_ns.model('AccountDetails', {
    'first_name': fields.String(required=True, description='First name of the user'),
    'last_name': fields.String(required=True, description='Last name of the user'),
    'email': fields.String(required=True, description='Email of the user'),
    'current_password': fields.String(description='Current password for changing the password'),
    'new_password': fields.String(description='New password for changing the password'),
    'confirm_new_password': fields.String(description='Confirm new password for changing the password')
})


address_model = user_ns.model('Address', {
    'country_name': fields.String(required=True, description='country name'),
    'first_name': fields.String(required=True, description='First name'),
    'last_name': fields.String(required=True, description='Last name'),
    'Address': fields.String(required=True, description='Address'),
    'Apartment_suite_etc_optional': fields.String(required=False, description='Apartment, suite, etc. (optional)'),
    'city': fields.String(required=True, description='City'),
    'phone_number': fields.String(required=True, description='Phone number')
})


product_model = api.model('Product', {
    'name': fields.String(required=True, description='Product name'),
    'description': fields.String(description='Product description'),
    'price': fields.Float(required=True, description='Product price'),
    'quantity': fields.Integer(required=True, description='Product quantity')
})

# Define the order response model
order_response_model = api.model('OrderResponse', {
    'order_id': fields.String,
    'user_id': fields.String,
    'products': fields.List(fields.Nested(product_model)),
    'product_total': fields.Float,
    'tax_amount': fields.Float,
    'tax_percentage': fields.Float,
    'shipping_charge': fields.Float,
    'total_amount': fields.Float,
    'status': fields.String,
    'razorpay_order_id': fields.String,
    'shipping_address': fields.Nested(address_model),
    'discount_code': fields.String(description='Discount Code Applied'),  # Added for discount code
    'discount_amount': fields.Float(description='Discount Amount Applied')  # Added for discount amount
})



# Define the order details model
order_details_model = api.model('OrderDetails', {
    'order_id': fields.String(description='Order ID'),
    'order_number': fields.String(description='Order Number'),
    'order_date': fields.DateTime(description='Order Date'),
    'status': fields.String(description='Order Status'),
    'products': fields.List(fields.Nested(product_model)),
    'total_amount': fields.Float(description='Total Amount'),
    'tax_amount': fields.Float(description='Tax Amount'),
    'shipping_charge': fields.Float(description='Shipping Charge'),
    'discount_code': fields.String(description='Discount Code'),
    'discount_amount': fields.Float(description='Discount Amount'),
    'shipping_address': fields.Nested(address_model),
    'payment_method': fields.String(description='Payment Method')
})

# Order Summary Model
order_summary_model = api.model('OrderSummary', {
    'product_total': fields.Float(description='Product Total'),
    'tax_amount': fields.Float(description='Tax Amount'),
    'tax_percentage': fields.Float(description='Tax Percentage'),
    'shipping_charge': fields.Float(description='Shipping Charge'),
    'total_amount': fields.Float(description='Total Amount'),
    'discount_amount': fields.Float(description='Discount Amount'),
    'discount_code': fields.String(description='Discount Code')
})


update_product_model = api.model('UpdateProduct', {
    'name': fields.String(description='Product name'),
    'description': fields.String(description='Product description'),
    'price': fields.Float(description='Product price'),
    'quantity': fields.Integer(description='Product quantity')
})

order_model = api.model('Orders', {
    'product_id': fields.String(required=True, description='Product ID'),
    'quantity': fields.Integer(required=True, description='Quantity'),
    'shipping_address_id': fields.String(required=True, description='Shipping Address ID'),
    'payment_method': fields.String(required=True, description='Payment Method', enum=['razorpay', 'cash_on_delivery']),
    'discount_code': fields.String(description='Discount Code')  # Added for discount handling
})

payment_success_model = api.model('PaymentSuccess', {
    'razorpay_order_id': fields.String(required=True, description='Razorpay Order ID'),
    'razorpay_payment_id': fields.String(required=True, description='Razorpay Payment ID'),
    'razorpay_signature': fields.String(required=True, description='Razorpay Signature')
})


appConf = {
    "OAUTH2_CLIENT_ID": "YOUR OAUTH2_CLIENT_ID",
    "OAUTH2_CLIENT_SECRET": "YOUR OAUTH2_CLIENT_SECRET",
    "OAUTH2_META_URL": "YOUR OAUTH2_META_URL",
    "FLASK_SECRET": "YOUR FLASK_SECRET",
    "FLASK_PORT": 5000,
    
}

app.secret_key = appConf.get("FLASK_SECRET")

oauth = OAuth(app)
# list of google scopes - https://developers.google.com/identity/protocols/oauth2/scopes
oauth.register(
    "myApp",
    client_id=appConf.get("OAUTH2_CLIENT_ID"),
    client_secret=appConf.get("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email https://www.googleapis.com/auth/user.birthday.read https://www.googleapis.com/auth/user.gender.read",
        # 'code_challenge_method': 'S256'  # enable PKCE
    },
    server_metadata_url=f'{appConf.get("OAUTH2_META_URL")}',
)


# Define a namespace for Google OAuth
ns_oauth = api.namespace('oauth', description='Google OAuth 2.0 operations')

@ns_oauth.route("/signin-google")
class GoogleCallback(Resource):
    def get(self):
        # fetch access token and id token using authorization code
        token = oauth.myApp.authorize_access_token()

        # fetch user data with access token
        personDataUrl = "https://people.googleapis.com/v1/people/me?personFields=genders,birthdays"
        personData = requests.get(personDataUrl, headers={
            "Authorization": f"Bearer {token['access_token']}"
        }).json()
        token["personData"] = personData
        # set complete user information in the session
        session["user"] = token
        return redirect(url_for("home"))

@ns_oauth.route("/google-login")
class GoogleLogin(Resource):
    def get(self):
        if "user" in session:
            abort(404)
        return oauth.myApp.authorize_redirect(redirect_uri=f'{appConf.get("NGROK_URL")}/signin-google')

@ns_oauth.route("/logout")
class Logout(Resource):
    def get(self):
        session.pop("user", None)
        return redirect(url_for("home"))

@app.route("/")
def home():
    return render_template("home.html", session=session.get("user"),
                           pretty=json.dumps(session.get("user"), indent=4))



# Define your routes within the namespace
# Register endpoint

@user_ns.route('/account/register')
class Register(Resource):
    @user_ns.doc('register_user')
    @user_ns.expect(register_model, validate=True)
    def post(self):
        data = request.json
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')

        if not first_name or not last_name or not email or not password:
            return {'error': 'First name, last name, email, and password are required'}, 400

        try:
            existing_user = mongo.db.users.find_one({'email': email})
            if existing_user:
                return {'error': 'Email already exists'}, 400

            hashed_password = generate_password_hash(password)
            mongo.db.users.insert_one({
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'password': hashed_password
            })
            return {'message': 'User registered successfully'}, 201
        except Exception as e:
            logging.error(f"Error registering user: {e}")
            return {'error': 'Error registering user'}, 500

# Login endpoint with JWT authentication

@user_ns.route('/account/login')
class Login(Resource):
    @user_ns.doc('login_user')
    @user_ns.expect(login_model, validate=True)
    def post(self):
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return {'error': 'Email and password are required'}, 400

        try:
            user = mongo.db.users.find_one({'email': email})
            if user and check_password_hash(user['password'], password):
                # Create a session for the user
                session['user_id'] = str(user['_id'])
                session['email'] = user['email']
                session.permanent = True  # Make the session permanent (lifetime set above)

                # Generate access token
                access_token = create_access_token(identity=str(user['_id']))
                return {'access_token': access_token, 'message': 'Login successful'}, 200
            else:
                return {'error': 'Invalid email or password'}, 401
        except Exception as e:
            logging.error(f"Error logging in: {e}")
            return {'error': 'Error logging in'}, 500
        

@user_ns.route('/account/logout')
class Logout(Resource):
    @user_ns.doc('logout_user')
    def post(self):
        session.pop('user_id', None)
        session.pop('email', None)
        return {'message': 'Logout successful'}, 200

@user_ns.route('/protected')
class Protected(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        return jsonify(logged_in_as=current_user_id)

@user_ns.route('/account/details')
class AccountDetails(Resource):
    @user_ns.doc('get_account_details')
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'User not logged in'}, 401

        try:
            user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0})  # Exclude password from the response
            if user:
                user['_id'] = str(user['_id'])  # Convert ObjectId to string
                return {'user': user}, 200
            else:
                return {'error': 'User not found'}, 404
        except Exception as e:
            logging.error(f"Error retrieving account details: {e}")
            return {'error': 'Error retrieving account details'}, 500

    @user_ns.doc('update_account_details')
    @user_ns.expect(account_details_model, validate=True)
    def put(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'User not logged in'}, 401

        data = request.json
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_new_password = data.get('confirm_new_password')

        if not first_name or not last_name or not email:
            return {'error': 'First name, last name, and email are required'}, 400

        update_fields = {'first_name': first_name, 'last_name': last_name, 'email': email}

        if current_password or new_password or confirm_new_password:
            if not current_password or not new_password or not confirm_new_password:
                return {'error': 'All password fields (current, new, confirm) are required for changing password'}, 400

            if new_password != confirm_new_password:
                return {'error': 'New password and confirm new password do not match'}, 400

            try:
                user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
                if user and check_password_hash(user['password'], current_password):
                    hashed_password = generate_password_hash(new_password)
                    update_fields['password'] = hashed_password
                else:
                    return {'error': 'Current password is incorrect'}, 401
            except Exception as e:
                logging.error(f"Error verifying current password: {e}")
                return {'error': 'Error verifying current password'}, 500

        try:
            mongo.db.users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': update_fields}
            )
            return {'message': 'Account details updated successfully'}, 200
        except Exception as e:
            logging.error(f"Error updating account details: {e}")
            return {'error': 'Error updating account details'}, 500



@user_ns.route('/account/address')
class AddAddress(Resource):
    @user_ns.doc('add_address')
    @user_ns.expect(address_model, validate=True)
    def post(self):
        if 'user_id' not in session:
            return {'error': 'User must be logged in to add an address'}, 401

        user_id = session['user_id']
        data = request.json
        country_name = data.get('country_name')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        Address = data.get('Address')
        Apartment_suite_etc_optional = data.get('Apartment_suite_etc_optional') # Apartement, suite, e.t.c(optional)
        city = data.get('city')
        phone_number = data.get('phone_number')

        if not first_name or not last_name or not Address or not city or not phone_number:
            return {'error': 'All required address fields must be provided'}, 400

        address = {
            'user_id': user_id,
            'country_name': country_name,
            'first_name': first_name,
            'last_name': last_name,
            'Address': Address,
            'Apartment_suite_etc_optional': Apartment_suite_etc_optional,
            'city': city,
            'phone_number': phone_number
        }

        try:
            address_id = mongo.db.addresses.insert_one(address).inserted_id
            return {'address_id': str(address_id)}, 201
        except Exception as e:
            logging.error(f"Error adding address: {e}")
            return {'error': 'Error adding address'}, 500

@user_ns.route('/account/addresses')
class GetAddresses(Resource):
    @user_ns.doc('get_addresses')
    def get(self):
        if 'user_id' not in session:
            return {'error': 'User must be logged in to view addresses'}, 401

        user_id = session['user_id']
        address_type = request.args.get('address_type')  # Optional filter by address type

        query = {'user_id': user_id}
        if address_type:
            query['address_type'] = address_type

        try:
            addresses = list(mongo.db.addresses.find(query))
            for address in addresses:
                address['_id'] = str(address['_id'])
            return addresses, 200
        except Exception as e:
            logging.error(f"Error retrieving addresses: {e}")
            return {'error': 'Error retrieving addresses'}, 500

@user_ns.route('/account/address/<string:address_id>')
class Address(Resource):
    @user_ns.doc('update_address')
    @user_ns.expect(address_model, validate=True)
    def put(self, address_id):
        if 'user_id' not in session:
            return {'error': 'User must be logged in to update an address'}, 401

        user_id = session['user_id']
        data = request.json
        country_name = data.get('country_name')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        Address = data.get('Address')
        Apartment_suite_etc_optional = data.get('Apartment_suite_etc_optional')
        city = data.get('city')
        phone_number = data.get('phone_number')

        if not first_name or not last_name or not Address or not city or not phone_number:
            return {'error': 'All required address fields must be provided'}, 400

        address = {
            'country_name': country_name,
            'first_name': first_name,
            'last_name': last_name,
            'Address': Address,
            'Apartment_suite_etc_optional': Apartment_suite_etc_optional,
            'city': city,
            'phone_number': phone_number
        }

        try:
            result = mongo.db.addresses.update_one(
                {'_id': ObjectId(address_id), 'user_id': user_id},
                {'$set': address}
            )

            if result.matched_count == 0:
                return {'error': 'Address not found or not authorized'}, 404

            return {'message': 'Address updated successfully'}, 200
        except Exception as e:
            logging.error(f"Error updating address: {e}")
            return {'error': 'Error updating address'}, 500


    @user_ns.doc('delete_address')
    def delete(self, address_id):
        if 'user_id' not in session:
            return {'error': 'User must be logged in to delete an address'}, 401

        user_id = session['user_id']
        try:
            result = mongo.db.addresses.delete_one({'_id': ObjectId(address_id), 'user_id': user_id})

            if result.deleted_count == 0:
                return {'error': 'Address not found or not authorized'}, 404

            return {'message': 'Address deleted successfully'}, 200
        except Exception as e:
            logging.error(f"Error deleting address: {e}")
            return {'error': 'Error deleting address'}, 500


# Define Swagger model for adding a product to the cart
cart_add_model = api.model('CartAdd', {
    'user_id': fields.String(required=True, description='ID of the user'),
    'product_id': fields.String(required=True, description='ID of the product'),
    'quantity': fields.Integer(required=True, description='Quantity of the product')
})

# Define Swagger model for updating cart item quantity
cart_update_model = api.model('CartUpdate', {
    'quantity': fields.Integer(required=True, description='New quantity of the cart item')
})

# Define Swagger model for deleting a cart item (requires no request body)
cart_delete_model = api.model('CartDelete', {
    'id': fields.String(required=True, description='ID of the cart item')
})

# Define Swagger model for clearing the cart (requires no request body)
cart_clear_model = api.model('CartClear', {})

# Define Swagger model for the response of GET method
cart_item_model = api.model('CartItem', {
    '_id': fields.String(description='ID of the cart item'),
    'user_id': fields.String(description='ID of the user'),
    'product_id': fields.String(description='ID of the product'),
    'quantity': fields.Integer(description='Quantity of the product')
})

# Resource class for managing the cart
@api.route('/api/cart')
class Cart(Resource):
    @api.expect(cart_add_model)
    def post(self):
        data = request.json
        user_id = data.get('user_id')
        product_id = data.get('product_id')
        quantity = data.get('quantity')

        if not user_id:
            return {'error': 'User ID is required'}, 400
        if not product_id or not quantity:
            return {'error': 'Product ID and quantity are required'}, 400

        try:
            cart_item = mongo.db.carts.find_one({'user_id': user_id, 'product_id': product_id})
            if cart_item:
                new_quantity = cart_item['quantity'] + quantity
                mongo.db.carts.update_one({'_id': cart_item['_id']}, {'$set': {'quantity': new_quantity}})
            else:
                mongo.db.carts.insert_one({'user_id': user_id, 'product_id': product_id, 'quantity': quantity})
            return {'message': 'Product added to cart'}, 200
        except Exception as e:
            logging.error(f"Error adding to cart: {e}")
            return {'error': 'Error adding to cart'}, 500

    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'User not logged in'}, 401

        try:
            cart_items = list(mongo.db.carts.find({'user_id': user_id}))
            detailed_cart_items = []
            for item in cart_items:
                product = mongo.db.products.find_one({'_id': ObjectId(item['product_id'])})
                if product:
                    item['_id'] = str(item['_id'])
                    product['_id'] = str(product['_id'])
                    item['product_details'] = product
                    detailed_cart_items.append(item)
            return detailed_cart_items, 200
        except Exception as e:
            logging.error(f"Error fetching cart: {e}")
            return {'error': 'Error fetching cart'}, 500


    

@api.route('/api/cart/<string:id>')
class CartItem(Resource):
    @api.expect(cart_update_model)
    def put(self, id):
        data = request.json
        user_id = session.get('user_id')
        new_quantity = data.get('quantity')

        if not user_id:
            return {'error': 'User not logged in'}, 401
        if not new_quantity or not isinstance(new_quantity, int) or new_quantity <= 0:
            return {'error': 'Valid quantity is required'}, 400

        try:
            cart_item = mongo.db.carts.find_one({'_id': ObjectId(id), 'user_id': user_id})
            if not cart_item:
                return {'error': 'Cart item not found'}, 404

            mongo.db.carts.update_one({'_id': ObjectId(id)}, {'$set': {'quantity': new_quantity}})
            return {'message': 'Cart item quantity updated successfully'}, 200
        except Exception as e:
            logging.error(f"Error updating cart quantity: {e}")
            return {'error': 'Error updating cart quantity'}, 500

    def delete(self, id):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'User not logged in'}, 401

        try:
            mongo.db.carts.delete_one({'_id': ObjectId(id), 'user_id': user_id})
            return {'message': 'Product removed from cart'}, 200
        except Exception as e:
            logging.error(f"Error removing from cart: {e}")
            return {'error': 'Error removing from cart'}, 500

@api.route('/api/cart/clear')
class ClearCart(Resource):
    def delete(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'User not logged in'}, 401

        try:
            mongo.db.carts.delete_many({'user_id': user_id})
            return {'message': 'Cart cleared successfully'}, 200
        except Exception as e:
            logging.error(f"Error clearing cart: {e}")
            return {'error': 'Error clearing cart'}, 500

# Add resources to the Flask-RestX Api
api.add_resource(Cart, '/api/cart')
api.add_resource(CartItem, '/api/cart/<string:id>')
api.add_resource(ClearCart, '/api/cart/clear')        

# Define Swagger model for adding a product to the wishlist
wishlist_add_model = api.model('WishlistAdd', {
    'product_id': fields.String(required=True, description='ID of the product')
})

# Define Swagger model for the response of GET method
wishlist_item_model = api.model('WishlistItem', {
    '_id': fields.String(description='ID of the wishlist item'),
    'user_id': fields.String(description='ID of the user'),
    'product_id': fields.String(description='ID of the product')
})

# Resource class for managing the wishlist
@api.route('/api/wishlist')
class Wishlist(Resource):
    @api.expect(wishlist_add_model)
    @api.response(200, 'Product added to wishlist')
    def post(self):
        data = request.json
        user_id = session.get('user_id')
        product_id = data.get('product_id')

        if not user_id:
            return {'error': 'User not logged in'}, 401
        if not product_id:
            return {'error': 'Product ID is required'}, 400

        try:
            wishlist_item = mongo.db.wishlists.find_one({'user_id': user_id, 'product_id': product_id})
            if wishlist_item:
                return {'message': 'Product already in wishlist'}, 200
            else:
                mongo.db.wishlists.insert_one({'user_id': user_id, 'product_id': product_id})
                return {'message': 'Product added to wishlist'}, 200
        except Exception as e:
            logging.error(f"Error adding to wishlist: {e}")
            return {'error': 'Error adding to wishlist'}, 500

    @api.doc('get_wishlist')
    @api.marshal_list_with(wishlist_item_model, envelope='items')
    def get(self):
        """
        Get all items in the wishlist for the logged in user
        """
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'User not logged in'}, 401

        try:
            wishlist_items = list(mongo.db.wishlists.find({'user_id': user_id}))
            for item in wishlist_items:
                item['_id'] = str(item['_id'])
            return wishlist_items, 200
        except Exception as e:
            logging.error(f"Error fetching wishlist: {e}")
            return {'error': 'Error fetching wishlist'}, 500

@api.route('/api/wishlist/<string:id>')
class WishlistItem(Resource):
    @api.response(200, 'Product removed from wishlist')
    def delete(self, id):
        """
        Remove a specific item from the wishlist
        """
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'User not logged in'}, 401

        try:
            mongo.db.wishlists.delete_one({'_id': ObjectId(id), 'user_id': user_id})
            return {'message': 'Product removed from wishlist'}, 200
        except Exception as e:
            logging.error(f"Error removing from wishlist: {e}")
            return {'error': 'Error removing from wishlist'}, 500

@api.route('/api/wishlist/clear')
class ClearWishlist(Resource):
    @api.doc('clear_wishlist')
    @api.response(200, 'Wishlist cleared successfully')
    def delete(self):
        """
        Clear all items in the wishlist for the logged in user
        """
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'User not logged in'}, 401

        try:
            result = mongo.db.wishlists.delete_many({'user_id': user_id})
            if result.deleted_count > 0:
                return {'message': 'Wishlist cleared'}, 200
            else:
                return {'message': 'Wishlist already empty'}, 200
        except Exception as e:
            logging.error(f"Error clearing wishlist: {e}")
            return {'error': 'Error clearing wishlist'}, 500

# Add resources to the Flask-RestX Api
api.add_resource(Wishlist, '/api/wishlist')
api.add_resource(WishlistItem, '/api/wishlist/<string:id>')
api.add_resource(ClearWishlist, '/api/wishlist/clear')

# Define Swagger model for tag creation and update
tag_model = api.model('Tag', {
    'name': fields.String(required=True, description='Name of the tag')
})

# Resource class for tags
@api.route('/api/tags')
class Tags(Resource):
    @api.expect(tag_model)
    def post(self):
        data = request.json
        name = data.get('name')
        if not name:
            logging.warning("Tag name is required but not provided")
            return {'error': 'Tag name is required'}, 400

        try:
            tag_id = mongo.db.tags.insert_one({'name': name}).inserted_id
            logging.info(f"Inserted tag with ID: {tag_id}")
            new_tag = mongo.db.tags.find_one({'_id': tag_id})
            if new_tag:
                new_tag['_id'] = str(new_tag['_id'])
                logging.info(f"Created tag: {new_tag}")
                return {'message': 'Tag created successfully', 'tag': new_tag}, 201
            else:
                logging.error("Failed to find the newly created tag")
                return {'error': 'Failed to retrieve created tag'}, 500
        except Exception as e:
            logging.error(f"Error creating tag: {e}")
            return {'error': 'Error creating tag'}, 500

    def get(self):
        try:
            tags = list(mongo.db.tags.find())
            logging.info(f"Fetched {len(tags)} tags from the database")
            for tag in tags:
                tag['_id'] = str(tag['_id'])
            logging.debug(f"Tags: {tags}")
            return tags, 200
        except Exception as e:
            logging.error(f"Error fetching tags: {e}")
            return {'error': 'Error fetching tags'}, 500

# Resource class for individual tag management
@api.route('/api/tags/<string:id>')
class TagItem(Resource):
    @api.expect(tag_model)
    def put(self, id):
        data = request.json
        name = data.get('name')
        if not name:
            logging.warning("Tag name is required but not provided")
            return {'error': 'Tag name is required'}, 400

        try:
            result = mongo.db.tags.update_one({'_id': ObjectId(id)}, {'$set': {'name': name}})
            if result.matched_count == 0:
                logging.warning(f"No tag found with ID: {id}")
                return {'error': 'Tag not found'}, 404
            logging.info(f"Updated tag with ID: {id}")
            return {'message': 'Tag updated successfully'}, 200
        except Exception as e:
            logging.error(f"Error updating tag {id}: {e}")
            return {'error': 'Error updating tag'}, 500

    def delete(self, id):
        try:
            result = mongo.db.tags.delete_one({'_id': ObjectId(id)})
            if result.deleted_count == 0:
                logging.warning(f"No tag found with ID: {id}")
                return {'error': 'Tag not found'}, 404
            logging.info(f"Deleted tag with ID: {id}")
            return {'message': 'Tag deleted successfully'}, 200
        except Exception as e:
            logging.error(f"Error deleting tag {id}: {e}")
            return {'error': 'Error deleting tag'}, 500

# Add resources to the Flask-RestX Api
api.add_resource(Tags, '/api/tags')
api.add_resource(TagItem, '/api/tags/<string:id>')

# Product Routes
@api.route('/api/products')
class ProductList(Resource):
    @api.expect(product_model)
    def post(self):
        data = request.json
        name = data.get('name')
        description = data.get('description')
        price = data.get('price')
        quantity = data.get('quantity')

        if not name or not isinstance(name, str):
            api.abort(400, 'Invalid product name')
        if not isinstance(price, (int, float)) or price <= 0:
            api.abort(400, 'Invalid product price')
        if not isinstance(quantity, int) or quantity < 0:
            api.abort(400, 'Invalid product quantity')

        try:
            product_id = mongo.db.products.insert_one({
                'name': name,
                'description': description,
                'price': price,
                'quantity': quantity
            }).inserted_id

            new_product = mongo.db.products.find_one({'_id': product_id})
            new_product['_id'] = str(new_product['_id'])

            logging.debug(f"Product created successfully: {new_product}")

            return {'message': 'Product created successfully', 'product': new_product}, 201

        except Exception as e:
            logging.error(f"Error creating product: {e}")
            api.abort(500, 'Error creating product')

    def get(self):
        try:
            products = list(mongo.db.products.find())
            for product in products:
                product['_id'] = str(product['_id'])
            return products, 200
        except Exception as e:
            logging.error(f"Error fetching products: {e}")
            api.abort(500, 'Error fetching products')

@api.route('/api/products/<string:id>')
class Product(Resource):
    def get(self, id):
        try:
            product = mongo.db.products.find_one_or_404({'_id': ObjectId(id)})
            product['_id'] = str(product['_id'])
            return product, 200
        except Exception as e:
            logging.error(f"Error fetching product {id}: {e}")
            api.abort(404, 'Product not found')

    @api.expect(update_product_model)
    def put(self, id):
        data = request.json
        name = data.get('name')
        description = data.get('description')
        price = data.get('price')
        quantity = data.get('quantity')

        if not name or not isinstance(name, str):
            api.abort(400, 'Invalid product name')
        if not isinstance(price, (int, float)) or price <= 0:
            api.abort(400, 'Invalid product price')
        if not isinstance(quantity, int) or quantity < 0:
            api.abort(400, 'Invalid product quantity')

        try:
            mongo.db.products.update_one({'_id': ObjectId(id)}, {'$set': {
                'name': name,
                'description': description,
                'price': price,
                'quantity': quantity
            }})

            return {'message': 'Product updated successfully'}, 200

        except Exception as e:
            logging.error(f"Error updating product {id}: {e}")
            api.abort(500, 'Error updating product')

    def delete(self, id):
        try:
            mongo.db.products.delete_one({'_id': ObjectId(id)})
            return {'message': 'Product deleted successfully'}, 200
        except Exception as e:
            logging.error(f"Error deleting product {id}: {e}")
            api.abort(500, 'Error deleting product')

# Order Route
# Constants for tax and shipping charges
# Utility functions
def convert_object_ids(data):
    """
    Recursively convert ObjectId and datetime to string in the given data structure.
    """
    if isinstance(data, list):
        return [convert_object_ids(item) for item in data]
    elif isinstance(data, dict):
        return {key: convert_object_ids(value) for key, value in data.items()}
    elif isinstance(data, ObjectId):
        return str(data)
    elif isinstance(data, datetime):
        return data.isoformat()
    else:
        return data

def validate_discount_code(code):
    """
    Dummy function for discount code validation.
    Replace with actual validation logic.
    """
    discount_codes = {
        'SUMMER10': {'type': 'percentage', 'value': 10},
        'FLAT50': {'type': 'flat', 'value': 50}
    }
    return discount_codes.get(code)

# Constants for tax and shipping charges
TAX_PERCENTAGE = 0.18  # 18% tax
SHIPPING_CHARGE = 50  # Fixed shipping charge

# Create Order Endpoint
@api.route('/api/create_order')
class CreateOrder(Resource):
    @api.expect(order_model)
    @api.response(201, 'Order created successfully', order_response_model)
    @api.response(400, 'Bad Request')
    @api.response(401, 'Unauthorized')
    @api.response(404, 'Not Found')
    @api.response(500, 'Internal Server Error')
    def post(self):
        if 'user_id' not in session:
            api.abort(401, 'User must be logged in to create an order')

        user_id = session['user_id']
        data = request.json
        product_id = data.get('product_id')
        quantity = data.get('quantity')
        shipping_address_id = data.get('shipping_address_id')
        payment_method = data.get('payment_method')
        discount_code = data.get('discount_code')

        logging.debug(f"Received create order request: {data}")

        try:
            product = mongo.db.products.find_one({'_id': ObjectId(product_id)})

            if not product:
                api.abort(404, 'Product not found')

            available_quantity = product.get('quantity', 0)

            if quantity > available_quantity:
                api.abort(400, f'Requested quantity {quantity} exceeds available quantity {available_quantity}')

            product_total = product.get('price', 0) * quantity

            discount_amount = 0
            if discount_code:
                discount = validate_discount_code(discount_code)
                if discount:
                    if discount['type'] == 'percentage':
                        discount_amount = product_total * (discount['value'] / 100)
                    elif discount['type'] == 'flat':
                        discount_amount = discount['value']
                    product_total -= discount_amount
                else:
                    api.abort(400, 'Invalid discount code')

            tax_amount = product_total * TAX_PERCENTAGE
            total_amount = product_total + tax_amount + SHIPPING_CHARGE

            address = mongo.db.addresses.find_one({'_id': ObjectId(shipping_address_id), 'user_id': user_id})
            if not address:
                logging.error(f"Address with ID {shipping_address_id} not found for user {user_id}")
                return {'message': 'Address not found'}, 404

            products = [{
                'product_id': str(product['_id']),
                'name': product['name'],
                'description': product.get('description', ''),
                'quantity': quantity,
                'price': product['price']
            }]

            order_data = {
                'user_id': user_id,
                'products': products,
                'product_total': product_total,
                'tax_amount': tax_amount,
                'tax_percentage': TAX_PERCENTAGE,
                'shipping_charge': SHIPPING_CHARGE,
                'total_amount': total_amount,
                'status': 'created',
                'shipping_address': address,
                'discount_code': discount_code,
                'discount_amount': discount_amount,
                'order_date': datetime.now(),
                'payment_method': payment_method
            }

            if payment_method == 'razorpay':
                razorpay_order_data = {
                    'amount': int(total_amount * 100),
                    'currency': 'INR',
                    'payment_capture': '1'
                }

                response = requests.post(
                    'https://api.razorpay.com/v1/orders',
                    auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET),
                    json=razorpay_order_data
                )
                response.raise_for_status()
                razorpay_order = response.json()
                order_data['razorpay_order_id'] = razorpay_order['id']

            elif payment_method == 'cash_on_delivery':
                order_data['status'] = 'cod_pending'

            order_id = mongo.db.orders.insert_one(order_data).inserted_id

            new_quantity = available_quantity - quantity
            mongo.db.products.update_one({'_id': ObjectId(product_id)}, {'$set': {'quantity': new_quantity}})

            logging.debug(f"Order created successfully: {order_data}")

            order_data['_id'] = str(order_id)
            order_data['shipping_address']['_id'] = str(order_data['shipping_address']['_id'])

            return convert_object_ids(order_data), 201

        except Exception as e:
            logging.error(f"Error creating order: {e}")
            api.abort(500, 'Error creating order')

# Order Details Endpoint
@api.route('/api/order/<string:order_id>')
class OrderDetails(Resource):
    @api.response(200, 'Success', order_details_model)
    @api.response(400, 'Bad Request')
    @api.response(401, 'Unauthorized')
    @api.response(404, 'Not Found')
    @api.response(500, 'Internal Server Error')
    def get(self, order_id):
        if 'user_id' not in session:
            api.abort(401, 'User must be logged in to view order details')

        user_id = session['user_id']

        logging.debug(f"Received request to fetch order details for order_id: {order_id}")

        try:
            order = mongo.db.orders.find_one({'_id': ObjectId(order_id), 'user_id': user_id})

            if not order:
                api.abort(404, 'Order not found')

            order = convert_object_ids(order)
            order['shipping_address']['_id'] = str(order['shipping_address']['_id'])

            return convert_object_ids(order), 200

        except Exception as e:
            logging.error(f"Error fetching order details: {e}")
            api.abort(500, 'Error fetching order details')

# Order Summary Endpoint
@api.route('/api/order_summary/<string:order_id>')
class OrderSummary(Resource):
    @api.response(200, 'Success', order_summary_model)
    @api.response(400, 'Bad Request')
    @api.response(401, 'Unauthorized')
    @api.response(404, 'Not Found')
    @api.response(500, 'Internal Server Error')
    def get(self, order_id):
        if 'user_id' not in session:
            api.abort(401, 'User must be logged in to view order summary')

        user_id = session['user_id']
        
        logging.debug(f"Received request to fetch order summary for order_id: {order_id}")

        try:
            order = mongo.db.orders.find_one({'_id': ObjectId(order_id), 'user_id': user_id})

            if not order:
                api.abort(404, 'Order not found')

            # Calculate the summary
            product_total = order.get('product_total', 0)
            tax_amount = order.get('tax_amount', 0)
            shipping_charge = order.get('shipping_charge', 0)
            total_amount = order.get('total_amount', 0)
            discount_amount = order.get('discount_amount', 0)
            discount_code = order.get('discount_code', '')

            summary = {
                'product_total': product_total,
                'tax_amount': tax_amount,
                'tax_percentage': TAX_PERCENTAGE,
                'shipping_charge': shipping_charge,
                'total_amount': total_amount,
                'discount_amount': discount_amount,
                'discount_code': discount_code
            }

            return summary, 200

        except Exception as e:
            logging.error(f"Error fetching order summary: {e}")
            api.abort(500, 'Error fetching order summary')



# Add resource to the Flask-RestX Api
api.add_resource(CreateOrder, '/api/create_order')
api.add_resource(OrderDetails, '/api/order/<string:order_id>')
api.add_resource(OrderSummary, '/api/order_summary/<string:order_id>')

@api.route('/api/payment_success')
class PaymentSuccess(Resource):
    @api.expect(payment_success_model)
    def post(self):
        data = request.json
        razorpay_order_id = data.get('razorpay_order_id')
        razorpay_payment_id = data.get('razorpay_payment_id')
        razorpay_signature = data.get('razorpay_signature')
        
        logging.debug(f"Received payment success data: {data}")

        generated_signature = hmac.new(
            RAZORPAY_KEY_SECRET.encode(),
            f"{razorpay_order_id}|{razorpay_payment_id}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        if generated_signature == razorpay_signature:
            try:
                mongo.db.orders.update_one({'razorpay_order_id': razorpay_order_id}, {'$set': {
                    'status': 'paid',
                    'razorpay_payment_id': razorpay_payment_id,
                    'razorpay_signature': razorpay_signature
                }})
                
                logging.debug(f"Order {razorpay_order_id} updated successfully")
                
                return {'message': 'Payment successful'}, 200
            except Exception as e:
                logging.error(f"Error updating order: {e}")
                api.abort(500, 'Error updating order')
        else:
            logging.error(f"Signature verification failed: {generated_signature} != {razorpay_signature}")
            api.abort(400, 'Signature verification failed')

# Swagger model for the checkout endpoint
checkout_model = api.model('Checkout', {
    'address_id': fields.String(required=True, description='ID of the address to deliver the order'),
    'payment_method': fields.String(required=True, description='Payment Method', enum=['razorpay', 'cash_on_delivery']),
    'discount_code': fields.String(description='Discount Code')  # Added for discount handling
})


# Define response models
product_model = api.model('Product', {
    'product_id': fields.String,
    'name': fields.String,
    'quantity': fields.Integer,
    'price': fields.Float
})

razorpay_order_model = api.model('RazorpayOrder', {
    'id': fields.String,
    'amount': fields.Integer,
    'currency': fields.String,
    'status': fields.String
})

checkout_response_model = api.model('CheckoutResponse', {
    'message': fields.String,
    'order_id': fields.String,
    'razorpay_order': fields.Nested(razorpay_order_model, required=False),
    'razorpay_order_id': fields.String(required=False, description='Razorpay Order ID')
})

# Resource class for checkout endpoint
# Constants for tax and shipping charges
TAX_PERCENTAGE = 0.18  # 18% tax
SHIPPING_CHARGE = 50  # Fixed shipping charge

@api.route('/api/checkout')
class Checkout(Resource):
    @api.expect(checkout_model)
    @api.response(201, 'Order created successfully', checkout_response_model)
    @api.response(400, 'Bad Request')
    @api.response(401, 'Unauthorized')
    @api.response(404, 'Not Found')
    @api.response(500, 'Internal Server Error')
    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'message': 'User not logged in'}, 401

        data = request.json
        address_id = data.get('address_id')
        payment_method = data.get('payment_method')
        discount_code = data.get('discount_code')

        if not address_id or not payment_method:
            return {'message': 'Address ID and Payment Method are required'}, 400

        try:
            # Verify address ID format
            address_obj_id = ObjectId(address_id)
            
            # Fetch the address from the database
            address = mongo.db.addresses.find_one({'_id': address_obj_id, 'user_id': user_id})
            if not address:
                logging.error(f"Address with ID {address_id} not found for user {user_id}")
                return {'message': 'Address not found'}, 404

            # Fetch all items in the cart
            cart_items = list(mongo.db.carts.find({'user_id': user_id}))
            if not cart_items:
                return {'message': 'Cart is empty'}, 400

            total_amount = 0
            products = []
            for item in cart_items:
                product = mongo.db.products.find_one({'_id': ObjectId(item['product_id'])})
                if not product:
                    return {'message': f'Product {item["product_id"]} not found'}, 404
                if product['quantity'] < item['quantity']:
                    return {'message': f'Not enough quantity for product {product["name"]}'}, 400
                total_amount += product['price'] * item['quantity']
                products.append({
                    'product_id': str(item['product_id']),
                    'name': product['name'],
                    'quantity': item['quantity'],
                    'price': product['price']
                })

            discount_amount = 0
            if discount_code:
                discount = validate_discount_code(discount_code)
                if discount:
                    if discount['type'] == 'percentage':
                        discount_amount = total_amount * (discount['value'] / 100)
                    elif discount['type'] == 'flat':
                        discount_amount = discount['value']
                    total_amount -= discount_amount
                    discount_info = {
                        'code': discount_code,
                        'amount': discount_amount,
                        'type': discount['type']
                    }
                else:
                    return {'message': 'Invalid discount code'}, 400
            else:
                discount_info = None

            # Calculate tax and final total amount
            tax_amount = total_amount * TAX_PERCENTAGE
            final_total_amount = total_amount + tax_amount + SHIPPING_CHARGE

            # Create Razorpay order if payment method is razorpay
            razorpay_order = None
            razorpay_order_id = None
            status = 'created'
            if payment_method == 'razorpay':
                amount_in_paise = int(final_total_amount * 100)
                razorpay_order_data = {
                    'amount': amount_in_paise,
                    'currency': 'INR',
                    'payment_capture': '1'
                }
                response = requests.post(
                    'https://api.razorpay.com/v1/orders',
                    auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET),
                    json=razorpay_order_data
                )
                response.raise_for_status()
                razorpay_order = response.json()
                razorpay_order_id = razorpay_order['id']
            elif payment_method == 'cash_on_delivery':
                status = 'cod_pending'

            # Insert order details into MongoDB
            order_id = mongo.db.orders.insert_one({
                'user_id': user_id,
                'products': products,
                'product_total': total_amount,
                'tax_amount': tax_amount,
                'TAX_PERCENTAGE': TAX_PERCENTAGE,
                'shipping_charge': SHIPPING_CHARGE,
                'total_amount': final_total_amount,
                'status': status,
                'razorpay_order_id': razorpay_order_id,
                'payment_method': payment_method,
                'shipping_address': address,
                'discount': discount_info
            }).inserted_id

            # Update product quantities
            for item in cart_items:
                mongo.db.products.update_one(
                    {'_id': ObjectId(item['product_id'])},
                    {'$inc': {'quantity': -item['quantity']}}
                )

            # Clear the cart
            mongo.db.carts.delete_many({'user_id': user_id})

            response_data = {
                'message': 'Order created successfully',
                'order_id': str(order_id),
                'discount': discount_info
            }
            if razorpay_order:
                response_data['razorpay_order'] = razorpay_order
                response_data['razorpay_order_id'] = razorpay_order_id

            return response_data, 201

        except Exception as e:
            logging.error(f"Error during checkout: {e}")
            return {'message': 'Error during checkout'}, 500

def validate_discount_code(code):
    # Dummy function for validation, replace with actual logic
    discount_codes = {
        'SUMMER10': {'type': 'percentage', 'value': 10},
        'FLAT50': {'type': 'flat', 'value': 50}
    }
    return discount_codes.get(code)



# Add resource to the Flask-RestX Api
api.add_resource(Checkout, '/api/checkout')






# Register namespace
api.add_namespace(user_ns, path='/api/users')
# Route to render an order form (example)
@app.route('/order_form', methods=['GET'])
def order_form():
    return render_template('order_form.html')

if __name__ == '__main__':
    app.run(debug=True)
