# E-commerce API

A comprehensive Flask-based RESTful API for an e-commerce platform, featuring user management, product operations, shopping cart functionality, wishlist management, order processing, and payment integration.

## Table of Contents

1. [Features](#features)
2. [Technologies Used](#technologies-used)
3. [Setup and Installation](#setup-and-installation)
4. [Environment Variables](#environment-variables)
5. [Running the Application](#running-the-application)
6. [API Documentation](#api-documentation)
7. [Detailed Endpoint Description](#detailed-endpoint-description)
8. [Authentication](#authentication)
9. [Database Schema](#database-schema)
10. [Error Handling](#error-handling)
11. [Testing](#testing)
12. [Deployment](#deployment)
13. [License](#license)

## Features

- User Management:
  - Registration, login, and logout
  - Account details retrieval and update
  - Address management
- Product Management:
  - CRUD operations for products
  - Product search and filtering
- Shopping Cart:
  - Add, update, remove items
  - View cart contents
- Wishlist:
  - Add and remove products
  - View wishlist
- Order Processing:
  - Create orders
  - View order history and details
- Payment Integration:
  - Razorpay integration for secure payments
  - Support for saved cards
- Discount System:
  - Apply discount codes
  - Calculate order totals with discounts
- Security:
  - JWT-based authentication
  - Password hashing
  - CORS support

## Technologies Used

- Python 3.x
- Flask: Web framework
- Flask-RESTX: API documentation and swagger UI
- PyMongo: MongoDB integration
- Razorpay: Payment gateway integration
- PyJWT: JWT token handling
- Werkzeug: Password hashing
- python-dotenv: Environment variable management
- Requests: HTTP library for API calls
- Cryptography: For encrypting sensitive data

## Setup and Installation

1. Clone the repository:
git clone https://github.com/yourusername/ecommerce-api.git
cd ecommerce-api

2. Create and activate a virtual environment:
python -m venv venv
source venv/bin/activate  # On Windows use venv\Scripts\activate

3. Install dependencies:
pip install -r requirements.txt

## Environment Variables

Create a `.env` file in the root directory with the following variables:
SECRET_KEY=your_flask_secret_key
RAZORPAY_KEY_ID=your_razorpay_key_id
RAZORPAY_KEY_SECRET=your_razorpay_key_secret
JWT_SECRET_KEY=your_jwt_secret_key
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname

## Running the Application

To run the application in debug mode:
python app.py

The API will be available at `http://localhost:5000`.

## API Documentation

Access the Swagger UI documentation at `http://localhost:5000/` when the application is running. This provides an interactive interface to explore and test all available endpoints.

## Detailed Endpoint Description

### User Management
- `POST /api/account/register`: Register a new user
- `POST /api/account/login`: User login
- `POST /api/account/logout`: User logout
- `GET /api/account/details`: Get user account details
- `PUT /api/account/details`: Update user account details
- `POST /api/account/address`: Add a new address
- `GET /api/account/addresses`: Get all addresses for a user
- `PUT /api/account/address/<address_id>`: Update an address
- `DELETE /api/account/address/<address_id>`: Delete an address

### Product Management
- `POST /api/products`: Add a new product
- `GET /api/products`: Get all products
- `GET /api/products/<product_id>`: Get a specific product
- `PUT /api/products/<product_id>`: Update a product
- `DELETE /api/products/<product_id>`: Delete a product

### Shopping Cart
- `POST /api/cart`: Add a product to cart
- `GET /api/cart`: View cart contents
- `PUT /api/cart/<item_id>`: Update cart item quantity
- `DELETE /api/cart/<item_id>`: Remove item from cart
- `DELETE /api/cart/clear`: Clear entire cart

### Wishlist
- `POST /api/wishlist`: Add a product to wishlist
- `GET /api/wishlist`: View wishlist
- `DELETE /api/wishlist/<item_id>`: Remove item from wishlist
- `DELETE /api/wishlist/clear`: Clear entire wishlist

### Order Processing
- `POST /api/create_order`: Create a new order
- `POST /api/checkout`: Process checkout
- `GET /api/order_summary`: Get order summary

### Payments
- `POST /api/payment_success`: Handle successful payment
- `POST /api/save_card`: Save a card for future use
- `GET /api/saved_cards`: Get all saved cards for a user

### Discounts
- `POST /api/apply_discount`: Apply a discount code

## Authentication

The API uses JWT for authentication. After successful login, include the JWT token in the Authorization header for protected routes:
Authorization: Bearer <your_jwt_token>

## Database Schema

The API uses MongoDB with the following main collections:
- `users`: Store user information
- `products`: Store product details
- `carts`: Store shopping cart information
- `wishlists`: Store wishlist items
- `orders`: Store order information
- `addresses`: Store user addresses
- `cards`: Store saved card information (encrypted)
- `discount_codes`: Store available discount codes

## Error Handling

The API provides detailed error messages and appropriate HTTP status codes for various scenarios, including input validation errors, authentication failures, and server errors.

## Testing

To run the test suite:
python -m unittest discover tests

Ensure you have a separate test database configured to avoid affecting production data.

## Deployment

For production deployment:
1. Set up a production MongoDB database
2. Configure environment variables for production
3. Use a production-grade WSGI server like Gunicorn
4. Set up NGINX as a reverse proxy
5. Ensure all debugging flags are turned off
6. Implement proper logging for production environment


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for detail
