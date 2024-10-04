from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error
import os

app = Flask(__name__)

# MySQL configurations (use environment variables for security)
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'MYSQL_USER')
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
    mysql.commit()

# Create operation
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
    return jsonify({'message': 'Product created successfully'})

# Read operation
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

# Update operation
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

# Delete operation
@app.route('/api/products/<int:id>', methods=['DELETE'])
def delete_product(id):
    cursor.execute("DELETE FROM products WHERE id=%s", (id,))
    mysql.commit()
    return jsonify({'message': 'Product deleted successfully'})

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
            <h2>Integrated the backend for the e-commerce merch page succesfully<h2>
        </div>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(debug=True)
