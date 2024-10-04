Here's the updated `README.md` file based on the new task requirements and updated code:

---

# Team7-E-commerce-Backend
Week 3 Task: Database Migration and Endpoint Creation
The Team  is assigned to:

Migrate the Database:

Migrate the current database to MongoDB.

Create Endpoints:

Develop endpoints for a merch-based eCommerce website, including:
Login
Cart
Wishlist
Tags
Other necessary endpoints



## README

# E-commerce Backend API

## Setup Instructions

### Prerequisites

- Python 3.x
- MongoDB server

### Installation

1. **Clone the repository:**

   ```sh
   git clone https://github.com/your-repo/ecommerce-backend.git
   cd ecommerce-backend
   ```

2. **Create a virtual environment and activate it:**

   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required packages:**

   ```sh
   pip install -r requirements.txt
   ```

4. **Set up environment variables:**

   Create a `.env` file in the project root or set the environment variables in your system:

   ```env
   MONGO_URI=mongodb://your_mongo_host:your_mongo_port/ecommerce_db
   RAZORPAY_KEY_ID=your_razorpay_key_id
   RAZORPAY_KEY_SECRET=your_razorpay_key_secret
   SECRET_KEY=your_secret_key
   ```

   Alternatively, you can export these variables directly in your terminal (useful for development):

   ```sh
   export MONGO_URI=mongodb://your_mongo_host:your_mongo_port/ecommerce_db
   export RAZORPAY_KEY_ID=your_razorpay_key_id
   export RAZORPAY_KEY_SECRET=your_razorpay_key_secret
   export SECRET_KEY=your_secret_key
   ```

5. **Run the Flask application:**

   ```sh
   flask run
   ```

### API Endpoints

#### User Authentication

1. **Register**

   **URL:** `/api/register`

   **Method:** `POST`

   **Description:** Registers a new user.

   **Request Body:**

   ```json
   {
     "first_name": "John",
     "last_name": "Doe",
     "email": "john.doe@example.com",
     "password": "password123"
   }
   ```

   **Response:**

   ```json
   {
     "message": "User registered successfully"
   }
   ```

2. **Login**

   **URL:** `/api/account/login`

   **Method:** `POST`

   **Description:** Logs in an existing user.

   **Request Body:**

   ```json
   {
     "email": "john.doe@example.com",
     "password": "password123"
   }
   ```

   **Response:**

   ```json
   {
     "message": "Login successful"
   }
   ```

3. **Logout**

   **URL:** `/api/account/logout`

   **Method:** `POST`

   **Description:** Logs out the current user.

   **Response:**

   ```json
   {
     "message": "Logout successful"
   }
   ```

#### Cart Management

1. **Add to Cart**

   **URL:** `/api/cart`

   **Method:** `POST`

   **Description:** Adds a product to the cart.

   **Request Body:**

   ```json
   {
     "product_id": "60d21b4667d0d8992e610c85",
     "quantity": 2
   }
   ```

   **Response:**

   ```json
   {
     "message": "Product added to cart"
   }
   ```

2. **Get Cart**

   **URL:** `/api/cart`

   **Method:** `GET`

   **Description:** Retrieves the current user's cart items.

   **Response:**

   ```json
   [
     {
       "_id": "60d21b4667d0d8992e610c85",
       "user_id": "60d21b4667d0d8992e610c85",
       "product_id": "60d21b4667d0d8992e610c85",
       "quantity": 2
     }
   ]
   ```

3. **Remove from Cart**

   **URL:** `/api/cart/<string:id>`

   **Method:** `DELETE`

   **Description:** Removes a product from the cart.

   **Response:**

   ```json
   {
     "message": "Product removed from cart"
   }
   ```

4. **Clear Cart**

   **URL:** `/api/cart/clear`

   **Method:** `DELETE`

   **Description:** Clears all items from the cart.

   **Response:**

   ```json
   {
     "message": "Cart cleared successfully"
   }
   ```

5. **Update Cart Quantity**

   **URL:** `/api/cart/<string:id>`

   **Method:** `PUT`

   **Description:** Updates the quantity of a cart item.

   **Request Body:**

   ```json
   {
     "quantity": 5
   }
   ```

   **Response:**

   ```json
   {
     "message": "Cart item quantity updated successfully"
   }
   ```

#### Wishlist Management

1. **Add to Wishlist**

   **URL:** `/api/wishlist`

   **Method:** `POST`

   **Description:** Adds a product to the wishlist.

   **Request Body:**

   ```json
   {
     "product_id": "60d21b4667d0d8992e610c85"
   }
   ```

   **Response:**

   ```json
   {
     "message": "Product added to wishlist"
   }
   ```

2. **Get Wishlist**

   **URL:** `/api/wishlist`

   **Method:** `GET`

   **Description:** Retrieves the current user's wishlist items.

   **Response:**

   ```json
   [
     {
       "_id": "60d21b4667d0d8992e610c85",
       "user_id": "60d21b4667d0d8992e610c85",
       "product_id": "60d21b4667d0d8992e610c85"
     }
   ]
   ```

3. **Remove from Wishlist**

   **URL:** `/api/wishlist/<string:id>`

   **Method:** `DELETE`

   **Description:** Removes a product from the wishlist.

   **Response:**

   ```json
   {
     "message": "Product removed from wishlist"
   }
   ```

4. **Clear Wishlist**

   **URL:** `/api/wishlist`

   **Method:** `DELETE`

   **Description:** Clears all items from the wishlist.

   **Response:**

   ```json
   {
     "message": "Wishlist cleared"
   }
   ```

#### Tag Management

1. **Create Tag**

   **URL:** `/api/tags`

   **Method:** `POST`

   **Description:** Creates a new tag.

   **Request Body:**

   ```json
   {
     "name": "New Tag"
   }
   ```

   **Response:**

   ```json
   {
     "message": "Tag created successfully",
     "tag": {
       "_id": "60d21b4667d0d8992e610c85",
       "name": "New Tag"
     }
   }
   ```

2. **Get Tags**

   **URL:** `/api/tags`

   **Method:** `GET`

   **Description:** Retrieves all tags.

   **Response:**

   ```json
   [
     {
       "_id": "60d21b4667d0d8992e610c85",
       "name": "Tag1"
     },
     {
       "_id": "60d21b4667d0d8992e610c86",
       "name": "Tag2"
     }
   ]
   ```

3. **Update Tag**

   **URL:** `/api/tags/<string:id>`

   **Method:** `PUT`

   **Description:** Updates an existing tag.

   **Request Body:**

   ```json
   {
     "name": "Updated Tag"
   }
   ```

   **Response:**

   ```json
   {
     "message": "Tag updated successfully"
   }
   ```

4. **Delete Tag**

   **URL:** `/api/tags/<string:id>`

   **Method:** `DELETE`

   **Description:** Deletes an existing tag.

   **Response:**

   ```json
   {
     "message": "Tag deleted successfully"
   }
   ```

#### Razorpay Integration

1. **Create Razorpay Order**

   **URL:** `/api/create_order`

   **Method:** `POST`

   **Description:** Creates a Razorpay order for a product.

   **Request Body:**

   ```json
   {
     "product_id": "60d21b4667d0d8992e610c85",
     "quantity": 2
   }
   ```

   **Response:**

   ```json
   {
     "id": "order_id",
     "amount": 3998,
     "currency": "INR",
     "status": "created"
   }
   ```

2. **Handle Payment Success**

   **URL:** `/api/payment_success`

   **Method:** `POST`

   **Description:** Handles the successful payment from Razorpay.

   **Request Body:**

   ```json
   {
     "razorpay_order_id": "order_id",
     "razorpay_payment_id": "payment_id",
     "razor

pay_signature": "signature"
   }
   ```

   **Response:**

   ```json
   {
     "message": "Payment successful",
     "order_id": "order_id",
     "payment_id": "payment_id"
   }
   ```

3. **Handle Payment Failure**

   **URL:** `/api/payment_failure`

   **Method:** `POST`

   **Description:** Handles the failed payment from Razorpay.

   **Request Body:**

   ```json
   {
     "order_id": "order_id",
     "reason": "payment failure reason"
   }
   ```

   **Response:**

   ```json
   {
     "message": "Payment failed",
     "order_id": "order_id",
     "reason": "payment failure reason"
   }
   ```

### Testing

To run tests, use the following command:

```sh
pytest
```

## Project Structure

```
ecommerce-backend/
├── app/
│   ├── __init__.py
│   ├── models.py
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── user_routes.py
│   │   ├── cart_routes.py
│   │   ├── wishlist_routes.py
│   │   ├── tag_routes.py
│   │   ├── payment_routes.py
│   └── services/
│       ├── __init__.py
│       ├── user_service.py
│       ├── cart_service.py
│       ├── wishlist_service.py
│       ├── tag_service.py
│       ├── payment_service.py
├── tests/
│   ├── __init__.py
│   ├── test_user.py
│   ├── test_cart.py
│   ├── test_wishlist.py
│   ├── test_tag.py
│   ├── test_payment.py
├── .env
├── .gitignore
├── requirements.txt
├── README.md
└── app.py
```
