# E-commerce Backend with Flask and Razorpay

This project is a Flask-based backend for an e-commerce merchandise page, integrated with the Razorpay payment gateway. It provides a comprehensive API for managing user accounts, product catalogs, shopping carts, wishlists, and order processing.

## Features

- User authentication and account management
- Product catalog management
- Shopping cart functionality
- Wishlist management
- Order processing with Razorpay integration
- Address management for users
- Tag management for products
- Secure HTTPS implementation

## Prerequisites

- Python 3.7+
- MongoDB
- Razorpay account and API keys

## Installation

1. Clone the repository:
git clone https://github.com/yourusername/ecommerce-backend.git
cd ecommerce-backend
Copy
2. Install the required packages:
pip install -r requirements.txt
Copy
3. Set up environment variables:
- `SECRET_KEY`: For Flask session encryption
- `MONGO_URI`: Your MongoDB connection string
- `RAZORPAY_KEY_ID`: Your Razorpay Key ID
- `RAZORPAY_KEY_SECRET`: Your Razorpay Key Secret

4. Generate SSL certificates for HTTPS:
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
Copy
## Running the Application

Run the Flask application:
python app.py
Copy
The server will start on `https://localhost:5000`.

## API Endpoints

### User Authentication

#### Register a new user
- **POST** `/api/register`
  ```json
  {
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "password": "securepassword"
  }
Login

POST /api/account/login
jsonCopy{
  "email": "john@example.com",
  "password": "securepassword"
}


Logout

POST /api/account/logout

Account Management
Update account details

PUT /api/account/details
jsonCopy{
  "first_name": "John",
  "last_name": "Doe",
  "email": "john@example.com"
}


Change password

PUT /api/account/password
jsonCopy{
  "current_password": "oldpassword",
  "new_password": "newpassword",
  "confirm_new_password": "newpassword"
}


Address Management
Add a new address

POST /api/account/address
jsonCopy{
  "address_line_1": "123 Main St",
  "city": "Anytown",
  "state": "State",
  "zip_code": "12345",
  "phone_number": "1234567890",
  "address_type": "shipping"
}


Get all addresses

GET /api/account/addresses

Cart Management
Add to cart

POST /api/cart
jsonCopy{
  "product_id": "product_id_here",
  "quantity": 2
}


Get cart

GET /api/cart

Remove from cart

DELETE /api/cart/<item_id>

Wishlist Management
Add to wishlist

POST /api/wishlist
jsonCopy{
  "product_id": "product_id_here"
}


Get wishlist

GET /api/wishlist

Remove from wishlist

DELETE /api/wishlist/<item_id>

Product Management
Create a new product

POST /api/products
jsonCopy{
  "name": "T-Shirt",
  "description": "A comfortable cotton t-shirt",
  "price": 19.99,
  "quantity": 100
}


Get all products

GET /api/products

Get a specific product

GET /api/products/<product_id>

Update a product

PUT /api/products/<product_id>
jsonCopy{
  "name": "Updated T-Shirt",
  "price": 24.99
}


Delete a product

DELETE /api/products/<product_id>

Order Processing
Create an order

POST /api/create_order
jsonCopy{
  "product_id": "product_id_here",
  "quantity": 2,
  "shipping_address_id": "address_id_here",
  "payment_method": "razorpay"
}


Checkout

POST /api/checkout
jsonCopy{
  "address_id": "address_id_here"
}


Tag Management
Create a new tag

POST /api/tags
jsonCopy{
  "name": "Summer Collection"
}


Get all tags

GET /api/tags

Update a tag

PUT /api/tags/<tag_id>
jsonCopy{
  "name": "Updated Tag Name"
}


Delete a tag

DELETE /api/tags/<tag_id>

Security

HTTPS is enforced for all connections.
Passwords are hashed before storing in the database.
Razorpay webhook signatures are verified for payment confirmation.

Error Handling
The API uses appropriate HTTP status codes and returns JSON responses with error messages when issues occur.
Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
License
This project is licensed under the MIT License - see the LICENSE file for details.
