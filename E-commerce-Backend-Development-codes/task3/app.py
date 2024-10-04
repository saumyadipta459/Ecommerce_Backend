from flask import Flask, request, jsonify, render_template, redirect, session
from flask_pymongo import PyMongo
import os
import razorpay
import hmac
import hashlib
import requests
import logging
from bson import ObjectId
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from bson.objectid import ObjectId

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')
app.permanent_session_lifetime = timedelta(days=7)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# MongoDB configurations
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/ecommerce_db')
mongo = PyMongo(app)

# Initialize Razorpay client
RAZORPAY_KEY_ID = os.getenv('RAZORPAY_KEY_ID', 'RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET', 'RAZORPAY_KEY_SECRET')
client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# HTTPS redirection middleware
@app.before_request
def before_request():
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

# User authentication routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')

    if not first_name or not last_name or not email or not password:
        return jsonify({'error': 'First name, last name, email, and password are required'}), 400

    try:
        existing_user = mongo.db.users.find_one({'email': email})
        if existing_user:
            return jsonify({'error': 'Email already exists'}), 400

        hashed_password = generate_password_hash(password)
        mongo.db.users.insert_one({
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': hashed_password
        })
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        logging.error(f"Error registering user: {e}")
        return jsonify({'error': 'Error registering user'}), 500

@app.route('/api/account/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    try:
        user = mongo.db.users.find_one({'email': email})
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            return jsonify({'message': 'Login successful'}), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401
    except Exception as e:
        logging.error(f"Error logging in: {e}")
        return jsonify({'error': 'Error logging in'}), 500

@app.route('/api/account/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logout successful'}), 200


# Cart management routes
@app.route('/api/cart', methods=['POST'])
def add_to_cart():
    data = request.json
    user_id = session.get('user_id')
    product_id = data.get('product_id')
    quantity = data.get('quantity')

    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401
    if not product_id or not quantity:
        return jsonify({'error': 'Product ID and quantity are required'}), 400

    try:
        cart_item = mongo.db.carts.find_one({'user_id': user_id, 'product_id': product_id})
        if cart_item:
            new_quantity = cart_item['quantity'] + quantity
            mongo.db.carts.update_one({'_id': cart_item['_id']}, {'$set': {'quantity': new_quantity}})
        else:
            mongo.db.carts.insert_one({'user_id': user_id, 'product_id': product_id, 'quantity': quantity})
        return jsonify({'message': 'Product added to cart'}), 200
    except Exception as e:
        logging.error(f"Error adding to cart: {e}")
        return jsonify({'error': 'Error adding to cart'}), 500

@app.route('/api/cart', methods=['GET'])
def get_cart():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401

    try:
        cart_items = list(mongo.db.carts.find({'user_id': user_id}))
        for item in cart_items:
            item['_id'] = str(item['_id'])
        return jsonify(cart_items), 200
    except Exception as e:
        logging.error(f"Error fetching cart: {e}")
        return jsonify({'error': 'Error fetching cart'}), 500

@app.route('/api/cart/<string:id>', methods=['DELETE'])
def remove_from_cart(id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401

    try:
        mongo.db.carts.delete_one({'_id': ObjectId(id), 'user_id': user_id})
        return jsonify({'message': 'Product removed from cart'}), 200
    except Exception as e:
        logging.error(f"Error removing from cart: {e}")
        return jsonify({'error': 'Error removing from cart'}), 500

# Clear cart route
@app.route('/api/cart/clear', methods=['DELETE'])
def clear_cart():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401

    try:
        mongo.db.carts.delete_many({'user_id': user_id})
        return jsonify({'message': 'Cart cleared successfully'}), 200
    except Exception as e:
        logging.error(f"Error clearing cart: {e}")
        return jsonify({'error': 'Error clearing cart'}), 500

# Update cart item quantity route
@app.route('/api/cart/<string:id>', methods=['PUT'])
def update_cart_quantity(id):
    data = request.json
    user_id = session.get('user_id')
    new_quantity = data.get('quantity')

    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401
    if not new_quantity or not isinstance(new_quantity, int) or new_quantity <= 0:
        return jsonify({'error': 'Valid quantity is required'}), 400

    try:
        cart_item = mongo.db.carts.find_one({'_id': ObjectId(id), 'user_id': user_id})
        if not cart_item:
            return jsonify({'error': 'Cart item not found'}), 404

        mongo.db.carts.update_one({'_id': ObjectId(id)}, {'$set': {'quantity': new_quantity}})
        return jsonify({'message': 'Cart item quantity updated successfully'}), 200
    except Exception as e:
        logging.error(f"Error updating cart quantity: {e}")
        return jsonify({'error': 'Error updating cart quantity'}), 500

# Wishlist management routes
@app.route('/api/wishlist', methods=['POST'])
def add_to_wishlist():
    data = request.json
    user_id = session.get('user_id')
    product_id = data.get('product_id')

    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401
    if not product_id:
        return jsonify({'error': 'Product ID is required'}), 400

    try:
        wishlist_item = mongo.db.wishlists.find_one({'user_id': user_id, 'product_id': product_id})
        if wishlist_item:
            return jsonify({'message': 'Product already in wishlist'}), 200
        else:
            mongo.db.wishlists.insert_one({'user_id': user_id, 'product_id': product_id})
            return jsonify({'message': 'Product added to wishlist'}), 200
    except Exception as e:
        logging.error(f"Error adding to wishlist: {e}")
        return jsonify({'error': 'Error adding to wishlist'}), 500

@app.route('/api/wishlist', methods=['GET'])
def get_wishlist():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401

    try:
        wishlist_items = list(mongo.db.wishlists.find({'user_id': user_id}))
        for item in wishlist_items:
            item['_id'] = str(item['_id'])
        return jsonify(wishlist_items), 200
    except Exception as e:
        logging.error(f"Error fetching wishlist: {e}")
        return jsonify({'error': 'Error fetching wishlist'}), 500

@app.route('/api/wishlist/<string:id>', methods=['DELETE'])
def remove_from_wishlist(id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401

    try:
        mongo.db.wishlists.delete_one({'_id': ObjectId(id), 'user_id': user_id})
        return jsonify({'message': 'Product removed from wishlist'}), 200
    except Exception as e:
        logging.error(f"Error removing from wishlist: {e}")
        return jsonify({'error': 'Error removing from wishlist'}), 500

@app.route('/api/wishlist', methods=['DELETE'])
def clear_wishlist():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401

    try:
        result = mongo.db.wishlists.delete_many({'user_id': user_id})
        if result.deleted_count > 0:
            return jsonify({'message': 'Wishlist cleared'}), 200
        else:
            return jsonify({'message': 'Wishlist already empty'}), 200
    except Exception as e:
        logging.error(f"Error clearing wishlist: {e}")
        return jsonify({'error': 'Error clearing wishlist'}), 500


# Tag management routes
@app.route('/api/tags', methods=['POST'])
def create_tag():
    data = request.json
    name = data.get('name')
    if not name:
        logging.warning("Tag name is required but not provided")
        return jsonify({'error': 'Tag name is required'}), 400

    try:
        tag_id = mongo.db.tags.insert_one({'name': name}).inserted_id
        logging.info(f"Inserted tag with ID: {tag_id}")
        new_tag = mongo.db.tags.find_one({'_id': tag_id})
        if new_tag:
            new_tag['_id'] = str(new_tag['_id'])
            logging.info(f"Created tag: {new_tag}")
            return jsonify({'message': 'Tag created successfully', 'tag': new_tag}), 201
        else:
            logging.error("Failed to find the newly created tag")
            return jsonify({'error': 'Failed to retrieve created tag'}), 500
    except Exception as e:
        logging.error(f"Error creating tag: {e}")
        return jsonify({'error': 'Error creating tag'}), 500

@app.route('/api/tags', methods=['GET'])
def get_tags():
    try:
        tags = list(mongo.db.tags.find())
        logging.info(f"Fetched {len(tags)} tags from the database")
        for tag in tags:
            tag['_id'] = str(tag['_id'])
        logging.debug(f"Tags: {tags}")
        return jsonify(tags), 200
    except Exception as e:
        logging.error(f"Error fetching tags: {e}")
        return jsonify({'error': 'Error fetching tags'}), 500

@app.route('/api/tags/<string:id>', methods=['PUT'])
def update_tag(id):
    data = request.json
    name = data.get('name')
    if not name:
        logging.warning("Tag name is required but not provided")
        return jsonify({'error': 'Tag name is required'}), 400

    try:
        result = mongo.db.tags.update_one({'_id': ObjectId(id)}, {'$set': {'name': name}})
        if result.matched_count == 0:
            logging.warning(f"No tag found with ID: {id}")
            return jsonify({'error': 'Tag not found'}), 404
        logging.info(f"Updated tag with ID: {id}")
        return jsonify({'message': 'Tag updated successfully'}), 200
    except Exception as e:
        logging.error(f"Error updating tag {id}: {e}")
        return jsonify({'error': 'Error updating tag'}), 500

@app.route('/api/tags/<string:id>', methods=['DELETE'])
def delete_tag(id):
    try:
        result = mongo.db.tags.delete_one({'_id': ObjectId(id)})
        if result.deleted_count == 0:
            logging.warning(f"No tag found with ID: {id}")
            return jsonify({'error': 'Tag not found'}), 404
        logging.info(f"Deleted tag with ID: {id}")
        return jsonify({'message': 'Tag deleted successfully'}), 200
    except Exception as e:
        logging.error(f"Error deleting tag {id}: {e}")
        return jsonify({'error': 'Error deleting tag'}), 500

# Route to create a new product
@app.route('/api/products', methods=['POST'])
def create_product():
    data = request.json
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    quantity = data.get('quantity')
    
    # Input validation
    if not name or not isinstance(name, str):
        return jsonify({'error': 'Invalid product name'}), 400
    if not isinstance(price, (int, float)) or price <= 0:
        return jsonify({'error': 'Invalid product price'}), 400
    if not isinstance(quantity, int) or quantity < 0:
        return jsonify({'error': 'Invalid product quantity'}), 400

    # Insert into MongoDB
    try:
        product_id = mongo.db.products.insert_one({
            'name': name,
            'description': description,
            'price': price,
            'quantity': quantity
        }).inserted_id

        new_product = mongo.db.products.find_one({'_id': product_id})
        
        # Convert ObjectId to string for serialization
        new_product['_id'] = str(new_product['_id'])

        logging.debug(f"Product created successfully: {new_product}")

        return jsonify({'message': 'Product created successfully', 'product': new_product}), 201

    except Exception as e:
        logging.error(f"Error creating product: {e}")
        return jsonify({'error': 'Error creating product'}), 500

# Route to fetch all products
@app.route('/api/products', methods=['GET'])
def get_all_products():
    try:
        products = list(mongo.db.products.find())

        # Convert ObjectId to string for serialization
        for product in products:
            product['_id'] = str(product['_id'])

        return jsonify(products), 200
    except Exception as e:
        logging.error(f"Error fetching products: {e}")
        return jsonify({'error': 'Error fetching products'}), 500

# Route to fetch a product by ID
@app.route('/api/products/<string:id>', methods=['GET'])
def get_product_by_id(id):
    try:
        product = mongo.db.products.find_one_or_404({'_id': ObjectId(id)})
        
        # Convert ObjectId to string for serialization
        product['_id'] = str(product['_id'])

        return jsonify(product), 200
    except Exception as e:
        logging.error(f"Error fetching product {id}: {e}")
        return jsonify({'error': 'Product not found'}), 404

# Route to update a product by ID
@app.route('/api/products/<string:id>', methods=['PUT'])
def update_product(id):
    data = request.json
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    quantity = data.get('quantity')
    
    # Input validation
    if not name or not isinstance(name, str):
        return jsonify({'error': 'Invalid product name'}), 400
    if not isinstance(price, (int, float)) or price <= 0:
        return jsonify({'error': 'Invalid product price'}), 400
    if not isinstance(quantity, int) or quantity < 0:
        return jsonify({'error': 'Invalid product quantity'}), 400

    # Update MongoDB record
    try:
        mongo.db.products.update_one({'_id': ObjectId(id)}, {'$set': {
            'name': name,
            'description': description,
            'price': price,
            'quantity': quantity
        }})

        return jsonify({'message': 'Product updated successfully'}), 200

    except Exception as e:
        logging.error(f"Error updating product {id}: {e}")
        return jsonify({'error': 'Error updating product'}), 500

# Route to delete a product by ID
@app.route('/api/products/<string:id>', methods=['DELETE'])
def delete_product(id):
    try:
        mongo.db.products.delete_one({'_id': ObjectId(id)})
        return jsonify({'message': 'Product deleted successfully'}), 200
    except Exception as e:
        logging.error(f"Error deleting product {id}: {e}")
        return jsonify({'error': 'Error deleting product'}), 500

# Route to create a Razorpay order
@app.route('/api/create_order', methods=['POST'])
def create_order():
    data = request.json
    product_id = data.get('product_id')
    quantity = data.get('quantity')

    logging.debug(f"Received create order request: {data}")
    
    # Retrieve product details from MongoDB
    try:
        product = mongo.db.products.find_one({'_id': ObjectId(product_id)})
        
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        available_quantity = product.get('quantity', 0)
        
        if quantity > available_quantity:
            return jsonify({'error': f'Requested quantity {quantity} exceeds available quantity {available_quantity}'}), 400

        amount = int(product.get('price', 0) * quantity * 100)  # Amount in paise

        razorpay_order_data = {
            'amount': amount,
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
            'product_id': product_id,
            'quantity': quantity,
            'amount': amount / 100.0,
            'status': 'created',
            'razorpay_order_id': razorpay_order['id']
        }).inserted_id

        # Update product quantity in MongoDB
        new_quantity = available_quantity - quantity
        mongo.db.products.update_one({'_id': ObjectId(product_id)}, {'$set': {'quantity': new_quantity}})

        logging.debug(f"Order created successfully: {razorpay_order}")
        
        return jsonify(razorpay_order), 201

    except Exception as e:
        logging.error(f"Error creating Razorpay order: {e}")
        return jsonify({'error': 'Error creating Razorpay order'}), 500

# Route to handle Razorpay payment success webhook
@app.route('/api/payment_success', methods=['POST'])
def payment_success():
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
            # Update order status in MongoDB
            mongo.db.orders.update_one({'razorpay_order_id': razorpay_order_id}, {'$set': {
                'status': 'paid',
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            }})
            
            logging.debug(f"Order {razorpay_order_id} updated successfully")
            
            return jsonify({'message': 'Payment successful'}), 200
        except Exception as e:
            logging.error(f"Error updating order: {e}")
            return jsonify({'error': 'Error updating order'}), 500
    else:
        logging.error(f"Signature verification failed: {generated_signature} != {razorpay_signature}")
        return jsonify({'error': 'Signature verification failed'}), 400

# Route to render an order form (example)
@app.route('/order_form', methods=['GET'])
def order_form():
    return render_template('order_form.html')

# Route to test MongoDB connection
@app.route('/test_mongo_connection', methods=['GET'])
def test_mongo_connection():
    try:
        mongo.db.products.find_one()  # Try a simple query to see if it throws any errors
        return jsonify({'message': 'MongoDB connection successful'}), 200
    except Exception as e:
        logging.error(f"MongoDB connection error: {e}")
        return jsonify({'error': 'MongoDB connection error'}), 500


# Example route
@app.route('/')
def index():
    return '''
     <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Server Status</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background: linear-gradient(to right, #00c6ff, #0072ff);
                color: white;
            }
            .container {
                text-align: center;
                background-color: rgba(255, 255, 255, 0.1);
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            }
            h1 {
                font-size: 3em;
                margin-bottom: 20px;
            }
            p {
                font-size: 1.2em;
                margin-bottom: 30px;
            }
            h2 {
                font-size: 1.2em;
                margin-bottom: 30px;
            }
            .button {
                background-color: #0072ff;
                color: white;
                border: none;
                padding: 10px 20px;
                text-decoration: none;
                font-size: 1em;
                border-radius: 5px;
                box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
                transition: background-color 0.3s ease, box-shadow 0.3s ease;
            }
            .button:hover {
                background-color: #005bb5;
                box-shadow: 0 8px 25px rgba(0, 0, 0, 0.2);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Server Created Successfully</h1>
            <p>Your Flask server is up and running!</p>
            <h2>Integrated the backend for the e-commerce merch page with Razorpay payment gateway successfully<h2>
        </div>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))

