# E-commerce Backend Development

## Overview

This project is an e-commerce backend built using Python Flask, MongoDB, and Razorpay for payment processing. It includes features for admin and user management, product CRUD operations, user authentication, cart management, wishlist handling, order creation, and more. The API documentation is integrated using Flask-RESTX.

## Task for Week 5

**Objective:** Complete the backend development and documentation according to the current Figma designs. Ensure that all changes are made on a single branch and that the code is up to date.

## Features

- **User Management:** Registration, login, logout, account details update, and password change functionalities.
- **Admin Management:** Admin registration, login, and CRUD operations for managing products and users.
- **Product Management:** Endpoints for creating, reading, updating, and deleting products.
- **Cart Management:** Add to cart, remove from cart, update cart items, and clear cart functionalities.
- **Wishlist Management:** Add to wishlist, remove from wishlist, and view wishlist functionalities.
- **Order Creation:** Integration with Razorpay and Cash on Delivery (COD) options.
- **Address Management:** Add, update, delete, and retrieve user addresses.
- **Tag Management:** Manage product tags.
- **API Documentation:** Integrated with Swagger using Flask-RESTX.

## Installation

1. **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2. **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4. **Set up environment variables:**
    Create a `.env` file in the project root and add the necessary environment variables (e.g., MongoDB URI, Razorpay API keys).

5. **Run the application:**
    ```bash
    flask run
    ```

## Usage

### User Endpoints

- **Register:** `POST /api/register`
- **Login:** `POST /api/login`
- **Logout:** `POST /api/logout`
- **Update Account Details:** `PUT /api/account`
- **Change Password:** `PUT /api/change-password`

### Admin Endpoints

- **Admin Register:** `POST /api/admin/register`
- **Admin Login:** `POST /api/admin/login`
- **Manage Users:** `GET /api/admin/users`, `PUT /api/admin/users/<id>`, `DELETE /api/admin/users/<id>`
- **Manage Products:** `POST /api/admin/products`, `GET /api/admin/products`, `PUT /api/admin/products/<id>`, `DELETE /api/admin/products/<id>`

### Product Endpoints

- **Get Products:** `GET /api/products`
- **Get Product by ID:** `GET /api/products/<id>`
- **Search Products:** `GET /api/products/search`

### Cart Endpoints

- **Add to Cart:** `POST /api/cart`
- **Remove from Cart:** `DELETE /api/cart/<id>`
- **Update Cart Item:** `PUT /api/cart/<id>`
- **Clear Cart:** `DELETE /api/cart`

### Wishlist Endpoints

- **Add to Wishlist:** `POST /api/wishlist`
- **Remove from Wishlist:** `DELETE /api/wishlist/<id>`
- **View Wishlist:** `GET /api/wishlist`

### Order Endpoints

- **Create Order:** `POST /api/create_order`
- **Get Orders:** `GET /api/orders`

### Address Endpoints

- **Add Address:** `POST /api/addresses`
- **Get Addresses:** `GET /api/addresses`
- **Update Address:** `PUT /api/addresses/<id>`
- **Delete Address:** `DELETE /api/addresses/<id>`

### Tag Endpoints

- **Manage Tags:** `POST /api/tags`, `GET /api/tags`, `PUT /api/tags/<id>`, `DELETE /api/tags/<id>`

## API Documentation

The API documentation is integrated using Swagger and Flask-RESTX. You can access the documentation at `/swagger` endpoint after running the application.

## Contributing

1. Fork the repository.
2. Create your feature branch: `git checkout -b feature/<branch_name>`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/<branch_name>`
5. Open a pull request.

## License

This project is licensed under the MIT License.
