from flask import Flask, request, jsonify, render_template, redirect
import mysql.connector
from mysql.connector import Error  
import os
import razorpay
import hmac
import hashlib
import requests  # Ensure this is imported for making HTTPS requests

app = Flask(_name_)

# MySQL configurations (use environment variables for security)
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', 'MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'ecommerce_db')

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB']
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error while connecting to MySQL: {e}")
        return None

# Initialize Razorpay client
RAZORPAY_KEY_ID = os.getenv('RAZORPAY_KEY_ID', 'RAZORPAY_KEY_ID')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET', 'RAZORPAY_KEY_SECRET')
client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# Create a cursor object to execute SQL queries
mysql = get_db_connection()
if mysql:
    cursor = mysql.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255),
            description TEXT,
            price DECIMAL(10, 2),
            quantity INT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INT AUTO_INCREMENT PRIMARY KEY,
            product_id INT,
            quantity INT,
            amount DECIMAL(10, 2),
            status VARCHAR(255),
            razorpay_order_id VARCHAR(255),
            razorpay_payment_id VARCHAR(255),
            razorpay_signature VARCHAR(255),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    """)
    mysql.commit()

# HTTPS redirection middleware
@app.before_request
def before_request():
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

# Create operation for products
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

    cursor.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)", 
                   (name, description, price, quantity))
    mysql.commit()
    
    # Debugging: Print new product details
    cursor.execute("SELECT * FROM products WHERE name=%s", (name,))
    new_product = cursor.fetchone()
    print(f"Product created successfully: {new_product}")
    
    return jsonify({'message': 'Product created successfully', 'product': new_product})

# Read operations for products
@app.route('/api/products', methods=['GET'])
def get_all_products():
   cursor.execute('SELECT * FROM products')
    products = cursor.fetchall()
    return jsonify(products)

@app.route('/api/products/<int:id>', methods=['GET'])
def get_product_by_id(id):
    cursor.execute('SELECT * FROM products WHERE id = %s', (id,))
    product = cursor.fetchone()
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    return jsonify(product)

# Update operation for products
@app.route('/api/products/<int:id>', methods=['PUT'])
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

    cursor.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s", 
                   (name, description, price, quantity, id))
    mysql.commit()
    return jsonify({'message': 'Product updated successfully'})
# Delete operation for products
@app.route('/api/products/<int:id>', methods=['DELETE'])
def delete_product(id):
    cursor.execute("DELETE FROM products WHERE id=%s", (id,))
    mysql.commit()
    return jsonify({'message': 'Product deleted successfully'})

# Create Razorpay order with HTTPS request
@app.route('/api/create_order', methods=['POST'])
def create_order():
    data = request.json
    product_id = data.get('product_id')
    quantity = data.get('quantity')

    print(f"Received create order request: {data}")
    
    cursor.execute('SELECT price, quantity FROM products WHERE id = %s', (product_id,))
    product = cursor.fetchone()
    
    print(f"Product query result: {product}")
    
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    available_quantity = product[1]
    
    if quantity > available_quantity:
        return jsonify({'error': f'Requested quantity {quantity} exceeds available quantity {available_quantity}'}), 400

    amount = int(product[0] * quantity * 100)  # Amount in paise

    razorpay_order_data = {
        'amount': amount,
        'currency': 'INR',
        'payment_capture': '1'
    }
    
    try:
        response = requests.post(
            'https://api.razorpay.com/v1/orders',
            auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET),
            json=razorpay_order_data
        )
        razorpay_order = response.json()

        cursor.execute("INSERT INTO orders (product_id, quantity, amount, status, razorpay_order_id) VALUES (%s, %s, %s, %s, %s)", 
                       (product_id, quantity, amount / 100.0, 'created', razorpay_order['id']))

        # Update the product quantity
        new_quantity = available_quantity - quantity
        cursor.execute("UPDATE products SET quantity=%s WHERE id=%s", (new_quantity, product_id))

        mysql.commit()
        
        print(f"Order created successfully: {razorpay_order}")
        
        return jsonify(razorpay_order)
    except Exception as e:
        print(f"Error creating Razorpay order: {e}")
        return jsonify({'error': 'Error creating Razorpay order'}), 500

# Handle Razorpay payment success
@app.route('/api/payment_success', methods=['POST'])
def payment_success():
    data = request.json
    razorpay_order_id = data.get('razorpay_order_id')
    razorpay_payment_id = data.get('razorpay_payment_id')
    razorpay_signature = data.get('razorpay_signature')
    
    print(f"Received payment success data: {data}")

    generated_signature = hmac.new(
        RAZORPAY_KEY_SECRET.encode(),
        f"{razorpay_order_id}|{razorpay_payment_id}".encode(),
        hashlib.sha256
    ).hexdigest()
    
    if generated_signature == razorpay_signature:
        try:
            cursor.execute("UPDATE orders SET status='paid', razorpay_payment_id=%s, razorpay_signature=%s WHERE razorpay_order_id=%s", 
                           (razorpay_payment_id, razorpay_signature, razorpay_order_id))
            mysql.commit()
            
            print(f"Order {razorpay_order_id} updated successfully")
            
            return jsonify({'message': 'Payment successful'})
        except Exception as e:
            print(f"Error updating order: {e}")
            return jsonify({'error': 'Error updating order'}), 500
    else:
        print(f"Signature verification failed: {generated_signature} != {razorpay_signature}")
        return jsonify({'error': 'Signature verification failed'}), 400
    
@app.route('/order_form', methods=['GET'])
def order_form():
    return render_template('order_form.html')

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
            <h2>Integrated the backend for the e-commerce merch page with Razorpay payment gateway succesfully<h2>
        </div>
    </body>
    </html>
    '''

if _name_ == '_main_':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
