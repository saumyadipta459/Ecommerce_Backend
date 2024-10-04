from flask import Flask, request, redirect, session, jsonify
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
from flask_cors import CORS
from functools import wraps
from bson import ObjectId
from flask import jsonify

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')
app.permanent_session_lifetime = timedelta(days=7)

# Enable CORS
CORS(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# MongoDB configurations
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/ecommerce_db')
mongo = PyMongo(app)

# Initialize Razorpay client
RAZORPAY_KEY_ID = os.getenv('RAZORPAY_KEY_ID', 'RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET', 'RAZORPAY_KEY_SECRET')
client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# Initialize Flask-RESTX
api = Api(app, version='1.0', title='E-commerce API', description='A simple e-commerce API')

# HTTPS redirection middleware
@app.before_request
def before_request():
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

# Admin namespace
admin_ns = Namespace('admin', description='Admin operations')
# User namespace
user_ns = Namespace('users', description='User operations')
# Admin registration and login models
register_model = api.model('AdminRegister', {
    'first_name': fields.String(required=True, description='Admin first name'),
    'last_name': fields.String(required=True, description='Admin last name'),
    'email': fields.String(required=True, description='Admin email'),
    'password': fields.String(required=True, description='Admin password')
})

login_model = api.model('AdminLogin', {
    'email': fields.String(required=True, description='Admin email'),
    'password': fields.String(required=True, description='Admin password')
})

# Define models
register_model = user_ns.model('Register', {
    'first_name': fields.String(required=True, description='First name of the user'),
    'last_name': fields.String(required=True, description='Last name of the user'),
    'email': fields.String(required=True, description='Email of the user'),
    'password': fields.String(required=True, description='Password of the user')
})

login_model = user_ns.model('Login', {
    'email': fields.String(required=True, description='Email of the user'),
    'password': fields.String(required=True, description='Password of the user')
})

account_details_model = user_ns.model('AccountDetails', {
    'first_name': fields.String(required=True, description='First name of the user'),
    'last_name': fields.String(required=True, description='Last name of the user'),
    'email': fields.String(required=True, description='Email of the user')
})

change_password_model = user_ns.model('ChangePassword', {
    'current_password': fields.String(required=True, description='Current password'),
    'new_password': fields.String(required=True, description='New password'),
    'confirm_new_password': fields.String(required=True, description='Confirm new password')
})



# Admin authentication decorator
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'admin_id' not in session:
            return {'error': 'Admin authentication required'}, 401
        return func(*args, **kwargs)
    return wrapper

# Admin registration route
@admin_ns.route('/register')
class AdminRegister(Resource):
    @admin_ns.doc('register_admin')
    @admin_ns.expect(register_model, validate=True)
    def post(self):
        data = request.json
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')

        if not (first_name and last_name and email and password):
            return {'error': 'Missing required fields'}, 400

        hashed_password = generate_password_hash(password)

        try:
            admin_id = mongo.db.admins.insert_one({
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'password': hashed_password
            }).inserted_id

            logging.debug(f"Admin registered successfully: {admin_id}")

            return {'message': 'Admin registered successfully'}, 201

        except Exception as e:
            logging.error(f"Error registering admin: {e}")
            return {'error': 'Registration failed'}, 500

# Admin login route
@admin_ns.route('/login')
class AdminLogin(Resource):
    @admin_ns.doc('login_admin')
    @admin_ns.expect(login_model, validate=True)
    def post(self):
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not (email and password):
            return {'error': 'Email and password are required'}, 400

        admin = mongo.db.admins.find_one({'email': email})

        if not admin or not check_password_hash(admin['password'], password):
            return {'error': 'Invalid credentials'}, 401

        session['admin_id'] = str(admin['_id'])

        logging.debug(f"Admin logged in successfully: {admin['_id']}")

        return {'message': 'Admin logged in successfully'}, 200

# Admin logout route
@admin_ns.route('/logout')
class AdminLogout(Resource):
    @admin_ns.doc('logout_admin')
    def post(self):
        session.pop('admin_id', None)
        return {'message': 'Admin logged out successfully'}, 200

# Product models
product_model = api.model('Product', {
    'name': fields.String(required=True, description='Product name'),
    'description': fields.String(description='Product description'),
    'price': fields.Float(required=True, description='Product price'),
    'quantity': fields.Integer(required=True, description='Product quantity')
})

update_product_model = api.model('UpdateProduct', {
    'name': fields.String(description='Product name'),
    'description': fields.String(description='Product description'),
    'price': fields.Float(description='Product price'),
    'quantity': fields.Integer(description='Product quantity')
})

# Product Routes
@api.route('/api/products')
class ProductList(Resource):
    @api.expect(product_model)
    @admin_required
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

    @admin_required
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
    @admin_required
    def get(self, id):
        try:
            product = mongo.db.products.find_one_or_404({'_id': ObjectId(id)})
            product['_id'] = str(product['_id'])
            return product, 200
        except Exception as e:
            logging.error(f"Error fetching product {id}: {e}")
            api.abort(404, 'Product not found')

    @api.expect(update_product_model)
    @admin_required
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

    @admin_required
    def delete(self, id):
        try:
            mongo.db.products.delete_one({'_id': ObjectId(id)})
            return {'message': 'Product deleted successfully'}, 200
        except Exception as e:
            logging.error(f"Error deleting product {id}: {e}")
            api.abort(500, 'Error deleting product')

# User management endpoints for admins
# Admin user management routes
def convert_object_ids(data):
    """
    Recursively convert ObjectId to string in the given data structure.
    """
    if isinstance(data, list):
        return [convert_object_ids(item) for item in data]
    elif isinstance(data, dict):
        return {key: convert_object_ids(value) for key, value in data.items()}
    elif isinstance(data, ObjectId):
        return str(data)
    else:
        return data

@admin_ns.route('/users')
class UserManagement(Resource):
    @admin_required
    def get(self):
        try:
            users = list(mongo.db.users.find())
            users = convert_object_ids(users)
            for user in users:
                user.pop('password', None)  # Exclude password field from the response
            
            logging.debug(f"Fetched users: {users}")

            return {'users': users}, 200
        except Exception as e:
            logging.error(f"Error fetching users: {e}")
            return {'error': 'Error fetching users'}, 500



@admin_ns.route('/users/<string:user_id>')
class UserDetail(Resource):
    @admin_required
    def get(self, user_id):
        try:
            user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
            if not user:
                return {'error': 'User not found'}, 404
            user['_id'] = str(user['_id'])
            return user, 200
        except Exception as e:
            logging.error(f"Error fetching user {user_id}: {e}")
            return {'error': 'Error fetching user'}, 500

    @admin_ns.expect(register_model, validate=True)
    @admin_required
    def put(self, user_id):
        data = request.json
        update_data = {k: v for k, v in data.items() if k in {'first_name', 'last_name', 'email', 'password'}}
        if 'password' in update_data:
            update_data['password'] = generate_password_hash(update_data['password'])

        try:
            result = mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
            if result.matched_count == 0:
                return {'error': 'User not found'}, 404
            return {'message': 'User updated successfully'}, 200
        except Exception as e:
            logging.error(f"Error updating user {user_id}: {e}")
            return {'error': 'Error updating user'}, 500

    @admin_required
    def delete(self, user_id):
        try:
            result = mongo.db.users.delete_one({'_id': ObjectId(user_id)})
            if result.deleted_count == 0:
                return {'error': 'User not found'}, 404
            return {'message': 'User deleted successfully'}, 200
        except Exception as e:
            logging.error(f"Error deleting user {user_id}: {e}")
            return {'error': 'Error deleting user'}, 500

# Define your routes within the namespace
@user_ns.route('/register')
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
                session['user_id'] = str(user['_id'])
                return {'message': 'Login successful'}, 200
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
        return {'message': 'Logout successful'}, 200

@user_ns.route('/account/details')
class UpdateAccountDetails(Resource):
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

        if not first_name or not last_name or not email:
            return {'error': 'First name, last name, and email are required'}, 400

        try:
            mongo.db.users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'first_name': first_name, 'last_name': last_name, 'email': email}}
            )
            return {'message': 'Account details updated successfully'}, 200
        except Exception as e:
            logging.error(f"Error updating account details: {e}")
            return {'error': 'Error updating account details'}, 500

@user_ns.route('/account/password')
class ChangePassword(Resource):
    @user_ns.doc('change_password')
    @user_ns.expect(change_password_model, validate=True)
    def put(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'User not logged in'}, 401

        data = request.json
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_new_password = data.get('confirm_new_password')

        if not current_password or not new_password or not confirm_new_password:
            return {'error': 'Current password, new password, and confirm new password are required'}, 400

        if new_password != confirm_new_password:
            return {'error': 'New password and confirm new password do not match'}, 400

        try:
            user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
            if user and check_password_hash(user['password'], current_password):
                hashed_password = generate_password_hash(new_password)
                mongo.db.users.update_one(
                    {'_id': ObjectId(user_id)},
                    {'$set': {'password': hashed_password}}
                )
                return {'message': 'Password changed successfully'}, 200
            else:
                return {'error': 'Current password is incorrect'}, 401
        except Exception as e:
            logging.error(f"Error changing password: {e}")
            return {'error': 'Error changing password'}, 500

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

# User Cart Resource class
@api.route('/api/cart')
class UserCart(Resource):
    @api.expect(cart_add_model)
    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'User not logged in'}, 401

        data = request.json
        product_id = data.get('product_id')
        quantity = data.get('quantity')

        if not product_id or not quantity:
            return {'error': 'Product ID and quantity are required'}, 400

        try:
            # Fetch product details to check available quantity
            product = mongo.db.products.find_one({'_id': ObjectId(product_id)})
            if not product:
                return {'error': 'Product not found'}, 404

            available_quantity = product.get('quantity', 0)

            # Check if requested quantity exceeds available quantity
            if quantity > available_quantity:
                return {'error': f'Requested quantity {quantity} exceeds available quantity {available_quantity}'}, 400

            # Check if the item already exists in the cart
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
            for item in cart_items:
                item['_id'] = str(item['_id'])
            return cart_items, 200
        except Exception as e:
            logging.error(f"Error fetching cart: {e}")
            return {'error': 'Error fetching cart'}, 500

@api.route('/api/cart/<string:id>')
class UserCartItem(Resource):
    @api.expect(cart_update_model)
    def put(self, id):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'User not logged in'}, 401

        data = request.json
        new_quantity = data.get('quantity')

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
class UserClearCart(Resource):
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

# Admin Cart Resource class
@api.route('/admin/api/cart')
class AdminCart(Resource):
    @admin_required
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
            # Fetch product details to check available quantity
            product = mongo.db.products.find_one({'_id': ObjectId(product_id)})
            if not product:
                return {'error': 'Product not found'}, 404

            available_quantity = product.get('quantity', 0)

            # Check if requested quantity exceeds available quantity
            if quantity > available_quantity:
                return {'error': f'Requested quantity {quantity} exceeds available quantity {available_quantity}'}, 400

            # Check if the item already exists in the cart
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

    @admin_required
    @api.doc(params={'user_id': 'ID of the user whose cart is to be fetched'})
    def get(self):
        user_id = request.args.get('user_id')
        if not user_id:
            return {'error': 'User ID is required'}, 400

        try:
            cart_items = list(mongo.db.carts.find({'user_id': user_id}))
            for item in cart_items:
                item['_id'] = str(item['_id'])
            return cart_items, 200
        except Exception as e:
            logging.error(f"Error fetching cart: {e}")
            return {'error': 'Error fetching cart'}, 500

@api.route('/admin/api/cart/<string:id>')
class AdminCartItem(Resource):
    @admin_required
    @api.expect(cart_update_model)
    @api.doc(params={'user_id': 'ID of the user whose cart item is to be updated'})
    def put(self, id):
        data = request.json
        user_id = request.args.get('user_id')
        if not user_id:
            return {'error': 'User ID is required'}, 400

        new_quantity = data.get('quantity')

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

    @admin_required
    @api.doc(params={'user_id': 'ID of the user whose cart item is to be deleted'})
    def delete(self, id):
        user_id = request.args.get('user_id')
        if not user_id:
            return {'error': 'User ID is required'}, 400

        try:
            mongo.db.carts.delete_one({'_id': ObjectId(id), 'user_id': user_id})
            return {'message': 'Product removed from cart'}, 200
        except Exception as e:
            logging.error(f"Error removing from cart: {e}")
            return {'error': 'Error removing from cart'}, 500

@api.route('/admin/api/cart/clear')
class AdminClearCart(Resource):
    @admin_required
    @api.doc(params={'user_id': 'ID of the user whose cart is to be cleared'})
    def delete(self):
        user_id = request.args.get('user_id')
        if not user_id:
            return {'error': 'User ID is required'}, 400

        try:
            mongo.db.carts.delete_many({'user_id': user_id})
            return {'message': 'Cart cleared successfully'}, 200
        except Exception as e:
            logging.error(f"Error clearing cart: {e}")
            return {'error': 'Error clearing cart'}, 500

# Add resources to the Flask-RestX Api
api.add_resource(UserCart, '/api/cart')
api.add_resource(UserCartItem, '/api/cart/<string:id>')
api.add_resource(UserClearCart, '/api/cart/clear')
api.add_resource(AdminCart, '/admin/api/cart')
api.add_resource(AdminCartItem, '/admin/api/cart/<string:id>')
api.add_resource(AdminClearCart, '/admin/api/cart/clear')

# Define Swagger model for adding a product to the wishlist
wishlist_add_model = api.model('WishlistAdd', {
    'user_id': fields.String(required=True, description='ID of the user'),
    'product_id': fields.String(required=True, description='ID of the product')
})

# Define Swagger model for the response of GET method
wishlist_item_model = api.model('WishlistItem', {
    '_id': fields.String(description='ID of the wishlist item'),
    'user_id': fields.String(description='ID of the user'),
    'product_id': fields.String(description='ID of the product')
})

# Utility function to validate ObjectId
def is_valid_objectid(value):
    try:
        ObjectId(value)
        return True
    except:
        return False

# Resource class for managing the wishlist for users
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
        if not product_id or not is_valid_objectid(product_id):
            return {'error': 'Valid product ID is required'}, 400

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

        if not is_valid_objectid(id):
            return {'error': 'Valid wishlist item ID is required'}, 400

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

# Resource class for managing the wishlist for admins
@api.route('/admin/api/wishlist')
class AdminWishlist(Resource):
    @admin_required
    @api.expect(wishlist_add_model)
    @api.response(200, 'Product added to wishlist')
    def post(self):
        data = request.json
        user_id = data.get('user_id')
        product_id = data.get('product_id')

        if not user_id or not is_valid_objectid(user_id):
            return {'error': 'Valid user ID is required'}, 400
        if not product_id or not is_valid_objectid(product_id):
            return {'error': 'Valid product ID is required'}, 400

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

    @admin_required
    @api.doc(params={'user_id': 'ID of the user whose wishlist is to be fetched'})
    @api.marshal_list_with(wishlist_item_model, envelope='items')
    def get(self):
        """
        Get all items in the wishlist for a specific user
        """
        user_id = request.args.get('user_id')
        if not user_id or not is_valid_objectid(user_id):
            return {'error': 'Valid user ID is required'}, 400

        try:
            wishlist_items = list(mongo.db.wishlists.find({'user_id': user_id}))
            for item in wishlist_items:
                item['_id'] = str(item['_id'])
            return wishlist_items, 200
        except Exception as e:
            logging.error(f"Error fetching wishlist: {e}")
            return {'error': 'Error fetching wishlist'}, 500

@api.route('/admin/api/wishlist/<string:id>')
class AdminWishlistItem(Resource):
    @admin_required
    @api.doc(params={'user_id': 'ID of the user whose wishlist item is to be deleted'})
    @api.response(200, 'Product removed from wishlist')
    def delete(self, id):
        """
        Remove a specific item from the wishlist for a specific user
        """
        user_id = request.args.get('user_id')
        if not user_id or not is_valid_objectid(user_id):
            return {'error': 'Valid user ID is required'}, 400

        if not is_valid_objectid(id):
            return {'error': 'Valid wishlist item ID is required'}, 400

        try:
            mongo.db.wishlists.delete_one({'_id': ObjectId(id), 'user_id': user_id})
            return {'message': 'Product removed from wishlist'}, 200
        except Exception as e:
            logging.error(f"Error removing from wishlist: {e}")
            return {'error': 'Error removing from wishlist'}, 500

@api.route('/admin/api/wishlist/clear')
class AdminClearWishlist(Resource):
    @admin_required
    @api.doc(params={'user_id': 'ID of the user whose wishlist is to be cleared'})
    @api.response(200, 'Wishlist cleared successfully')
    def delete(self):
        """
        Clear all items in the wishlist for a specific user
        """
        user_id = request.args.get('user_id')
        if not user_id or not is_valid_objectid(user_id):
            return {'error': 'Valid user ID is required'}, 400

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
api.add_resource(AdminWishlist, '/admin/api/wishlist')
api.add_resource(AdminWishlistItem, '/admin/api/wishlist/<string:id>')
api.add_resource(AdminClearWishlist, '/admin/api/wishlist/clear')

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

# Define Swagger model for address creation and update
address_model = user_ns.model('Address', {
    'address_line_1': fields.String(required=True, description='Address line 1'),
    'city': fields.String(required=True, description='City'),
    'state': fields.String(required=True, description='State'),
    'zip_code': fields.String(required=True, description='Zip code'),
    'phone_number': fields.String(required=True, description='Phone number'),
    'address_type': fields.String(required=True, description='Address type (shipping, billing, or both)')
})

@user_ns.route('/account/address')
class AddAddress(Resource):
    @user_ns.doc('add_address')
    @user_ns.expect(address_model, validate=True)
    def post(self):
        if 'user_id' not in session:
            return {'error': 'User must be logged in to add an address'}, 401

        user_id = session['user_id']
        data = request.json
        address_line_1 = data.get('address_line_1')
        city = data.get('city')
        state = data.get('state')
        zip_code = data.get('zip_code')
        phone_number = data.get('phone_number')
        address_type = data.get('address_type')

        if not address_line_1 or not city or not state or not zip_code or not phone_number or not address_type:
            return {'error': 'All address fields and address type are required'}, 400

        address = {
            'user_id': user_id,
            'address_line_1': address_line_1,
            'city': city,
            'state': state,
            'zip_code': zip_code,
            'phone_number': phone_number,
            'address_type': address_type
        }

        try:
            address_id = mongo.insert_one(address).inserted_id
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
            addresses = list(mongo.find(query))
            for address in addresses:
                address['_id'] = str(address['_id'])
            return addresses, 200
        except Exception as e:
            logging.error(f"Error retrieving addresses: {e}")
            return {'error': 'Error retrieving addresses'}, 500

@user_ns.route('/account/address/<string:address_id>')
class ManageAddress(Resource):
    @user_ns.doc('update_address')
    @user_ns.expect(address_model, validate=True)
    def put(self, address_id):
        if 'user_id' not in session:
            return {'error': 'User must be logged in to update an address'}, 401

        user_id = session['user_id']
        data = request.json
        address_line_1 = data.get('address_line_1')
        city = data.get('city')
        state = data.get('state')
        zip_code = data.get('zip_code')
        phone_number = data.get('phone_number')
        address_type = data.get('address_type')

        if not address_line_1 or not city or not state or not zip_code or not phone_number or not address_type:
            return {'error': 'All address fields and address type are required'}, 400

        address = {
            'address_line_1': address_line_1,
            'city': city,
            'state': state,
            'zip_code': zip_code,
            'phone_number': phone_number,
            'address_type': address_type
        }

        try:
            result = mongo.update_one(
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
            result = mongo.delete_one({'_id': ObjectId(address_id), 'user_id': user_id})

            if result.deleted_count == 0:
                return {'error': 'Address not found or not authorized'}, 404

            return {'message': 'Address deleted successfully'}, 200
        except Exception as e:
            logging.error(f"Error deleting address: {e}")
            return {'error': 'Error deleting address'}, 500

# Add resources to the Flask-RestX Api
api.add_resource(AddAddress, '/account/address')
api.add_resource(GetAddresses, '/account/addresses')
api.add_resource(ManageAddress, '/account/address/<string:address_id>')

# Define Swagger model for order creation
order_model = api.model('Order', {
    'product_id': fields.String(required=True, description='Product ID'),
    'quantity': fields.Integer(required=True, description='Quantity of product'),
    'shipping_address_id': fields.String(required=True, description='Shipping Address ID'),
    'payment_method': fields.String(required=True, description='Payment method (razorpay or cash_on_delivery)')
})

@api.route('/api/create_order')
class CreateOrder(Resource):
    @api.expect(order_model, validate=True)
    def post(self):
        if 'user_id' not in session:
            api.abort(401, 'User must be logged in to create an order')

        user_id = session['user_id']
        data = request.json
        product_id = data.get('product_id')
        quantity = data.get('quantity')
        shipping_address_id = data.get('shipping_address_id')
        payment_method = data.get('payment_method')

        logging.debug(f"Received create order request: {data}")

        try:
            product = mongo.db.products.find_one({'_id': ObjectId(product_id)})

            if not product:
                api.abort(404, 'Product not found')

            available_quantity = product.get('quantity', 0)

            if quantity > available_quantity:
                api.abort(400, f'Requested quantity {quantity} exceeds available quantity {available_quantity}')

            amount = int(product.get('price', 0) * quantity * 100)  # Amount in paise
            subtotal = amount / 100.0
            shipping = 7.24
            taxes = 10
            total_amount = subtotal + shipping + taxes

            order_data = {
                'user_id': user_id,
                'product_id': product_id,
                'quantity': quantity,
                'amount': total_amount,
                'subtotal': subtotal,
                'shipping': shipping,
                'taxes': taxes,
                'payment_method': payment_method,
                'status': 'created',  # Initial status for all orders
                'shipping_address_id': shipping_address_id
            }

            if payment_method == 'razorpay':
                razorpay_order_data = {
                    'amount': int(total_amount * 100),  # Amount in paise
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
                order_data['status'] = 'cod_pending'  # Update status for COD orders

            order_id = mongo.db.orders.insert_one(order_data).inserted_id

            new_quantity = available_quantity - quantity
            mongo.db.products.update_one({'_id': ObjectId(product_id)}, {'$set': {'quantity': new_quantity}})

            logging.debug(f"Order created successfully: {order_data}")

            return {'order_id': str(order_id), 'razorpay_order_id': order_data.get('razorpay_order_id')}, 201

        except Exception as e:
            logging.error(f"Error creating order: {e}")
            api.abort(500, 'Error creating order')

# Add resources to the Flask-RestX Api
api.add_resource(CreateOrder, '/api/create_order')

#model for payement
payment_success_model = api.model('PaymentSuccess', {
    'razorpay_order_id': fields.String(required=True, description='Razorpay Order ID'),
    'razorpay_payment_id': fields.String(required=True, description='Razorpay Payment ID'),
    'razorpay_signature': fields.String(required=True, description='Razorpay Signature')
})

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

# Add resources to the Flask-RestX Api
api.add_resource(PaymentSuccess, '/api/payment_success')

# Model for checkout response
checkout_model = api.model('Checkout', {
    'message': fields.String(required=True, description='Order status message'),
    'order_id': fields.String(required=True, description='Order ID'),
    'razorpay_order': fields.Raw(required=True, description='Razorpay order details')
})


# Define Swagger model for the checkout request
checkout_model = api.model('Checkout', {
    'address_id': fields.String(required=True, description='ID of the address to deliver the order')
})

# Resource class for checkout endpoint
class Checkout(Resource):
    @api.expect(checkout_model)
    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            abort(401, message='User not logged in')

        data = request.json
        address_id = data.get('address_id')

        if not address_id:
            abort(400, message='Address ID is required')

        try:
            # Verify address ID format
            address_obj_id = ObjectId(address_id)

            # Fetch the address from the database
            address = mongo.db.addresses.find_one({'_id': address_obj_id, 'user_id': user_id})
            if not address:
                logging.error(f"Address with ID {address_id} not found for user {user_id}")
                abort(404, message='Address not found')

            # Fetch all items in the cart
            cart_items = list(mongo.db.carts.find({'user_id': user_id}))

            if not cart_items:
                abort(400, message='Cart is empty')

            total_amount = 0
            products = []

            for item in cart_items:
                product = mongo.db.products.find_one({'_id': ObjectId(item['product_id'])})
                if not product:
                    abort(404, message=f'Product {item["product_id"]} not found')
                
                if product['quantity'] < item['quantity']:
                    abort(400, message=f'Not enough quantity for product {product["name"]}')

                total_amount += product['price'] * item['quantity']
                products.append({
                    'product_id': str(item['product_id']),  # Convert ObjectId to string for JSON serialization
                    'name': product['name'],
                    'quantity': item['quantity'],
                    'price': product['price']
                })

            # Create Razorpay order
            amount_in_paise = int(total_amount * 100)
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

            # Insert order details into MongoDB
            order_id = mongo.db.orders.insert_one({
                'user_id': user_id,
                'products': products,
                'total_amount': total_amount,
                'status': 'created',
                'razorpay_order_id': razorpay_order['id'],
                'shipping_address': address  # Attach the address to the order
            }).inserted_id

            # Update product quantities
            for item in cart_items:
                mongo.db.products.update_one(
                    {'_id': ObjectId(item['product_id'])},
                    {'$inc': {'quantity': -item['quantity']}}
                )

            # Clear the cart
            mongo.db.carts.delete_many({'user_id': user_id})

            return {
                'message': 'Order created successfully',
                'order_id': str(order_id),
                'razorpay_order': razorpay_order
            }, 201

        except Exception as e:
            logging.error(f"Error during checkout: {e}")
            abort(500, message='Error during checkout')

# Add resource to the Flask-RestX Api
api.add_resource(Checkout, '/api/checkout')


# Add namespaces to API
api.add_namespace(admin_ns)
api.add_namespace(user_ns)

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
