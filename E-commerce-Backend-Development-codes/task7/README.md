Here's the README.md content in a format you can directly copy and paste:

```
# E-commerce API

This is a Flask-based RESTful API for an e-commerce platform. It provides endpoints for user management, product management, cart operations, wishlist management, order processing, and payment integration with Razorpay.

## Features

- User authentication and authorization using JWT
- Product management (CRUD operations)
- Shopping cart functionality
- Wishlist management
- Order processing and checkout
- Payment integration with Razorpay
- Discount code support
- Address management for users
- Google OAuth 2.0 integration

## Technologies Used

- Python 3.x
- Flask
- Flask-RESTx for API documentation
- PyMongo for MongoDB integration
- Razorpay for payment processing
- JWT for authentication
- Google OAuth 2.0 for social login

## Setup and Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/ecommerce-api.git
   cd ecommerce-api
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   Create a `.env` file in the root directory and add the following variables:
   ```
   MONGO_URI=your_mongodb_uri
   SECRET_KEY=your_secret_key
   JWT_SECRET_KEY=your_jwt_secret_key
   RAZORPAY_KEY_ID=your_razorpay_key_id
   RAZORPAY_KEY_SECRET=your_razorpay_key_secret
   OAUTH2_CLIENT_ID=your_google_oauth_client_id
   OAUTH2_CLIENT_SECRET=your_google_oauth_client_secret
   OAUTH2_META_URL=https://accounts.google.com/.well-known/openid-configuration
   ```

4. Run the application:
   ```
   python app.py
   ```

## API Documentation

Once the server is running, you can access the Swagger UI documentation at:
```
http://localhost:5000/
```

This will provide an interactive interface to explore and test all available API endpoints.

## Main Endpoints

- User Management: `/api/users/*`
- Product Management: `/api/products`
- Cart Operations: `/api/cart`
- Wishlist Management: `/api/wishlist`
- Order Processing: `/api/create_order`, `/api/order/*`
- Checkout: `/api/checkout`
- Payment: `/api/payment_success`

## Authentication

The API uses JWT for authentication. To access protected endpoints, include the JWT token in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.
```
