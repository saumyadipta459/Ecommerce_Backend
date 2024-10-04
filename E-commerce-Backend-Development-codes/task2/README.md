Here’s the updated README.md file to reflect the changes based on the given Flask application code:

---

# Team7-E-commerce-Backend

The task involves integrating the backend for the e-commerce merch page with Razorpay payment Gateway. This includes setting up the necessary databases, APIs, and server-side logic to support the merchandise functionalities.

## README

# E-commerce Backend API

## Setup Instructions

### Prerequisites

- Python 3.x
- MySQL server

### Installation

1. *Clone the repository:*

   sh
   git clone https://github.com/your-repo/ecommerce-backend.git
   cd ecommerce-backend
   

2. *Create a virtual environment and activate it:*

   sh
 python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   

3. *Install the required packages:*

   sh
   pip install -r requirements.txt
   

4. *Set up environment variables:*

   Create a .env file in the project root or set the environment variables in your system:

   env
   MYSQL_HOST=your_mysql_host
   MYSQL_USER=your_mysql_user
   MYSQL_PASSWORD=your_mysql_password
   MYSQL_DB=ecommerce_db
   RAZORPAY_KEY_ID=your_razorpay_key_id
   RAZORPAY_KEY_SECRET=your_razorpay_key_secret
   

   Alternatively, you can export these variables directly in your terminal (useful for development):

   sh
   export MYSQL_HOST=your_mysql_host
   export MYSQL_USER=your_mysql_user
   export MYSQL_PASSWORD=your_mysql_password
export MYSQL_DB=ecommerce_db
   export RAZORPAY_KEY_ID=your_razorpay_key_id
   export RAZORPAY_KEY_SECRET=your_razorpay_key_secret
   

5. *Run the Flask application:*

   sh
   flask run
   

### API Endpoints

#### 1. Create Product

*URL:* /api/products

*Method:* POST

*Description:* Creates a new product in the inventory.

*Request Body:*

| Field       | Type    | Description                | Required |
|-------------|---------|----------------------------|----------|
| name        | string  | The name of the product    | Yes      |
| description | string  | A short description        | No       |
| price       | number  | The price of the product   | Yes      |
| quantity    | integer | The stock quantity         | Yes      |

*Request Example:*

json
{
 "name": "Sample Product",
  "description": "This is a sample product.",
  "price": 19.99,
  "quantity": 100
}


*Response:*

- *Status Code:* 200 OK

*Response Body:*

json
{
  "message": "Product created successfully",
  "product": {
    "id": 1,
    "name": "Sample Product",
    "description": "This is a sample product.",
    "price": 19.99,
    "quantity": 100
  }
}


#### 2. Get All Products

*URL:* /api/products

*Method:* GET

*Description:* Retrieves a list of all products in the inventory.

*Response:*
- *Status Code:* 200 OK

*Response Body:*

json
[
  {
    "id": 1,
    "name": "Sample Product",
    "description": "This is a sample product.",
    "price": 19.99,
    "quantity": 100
  },
  ...
]


#### 3. Get Product by ID

*URL:* /api/products/<int:id>

*Method:* GET

*Description:* Retrieves the details of a specific product by its ID.

*URL Parameter:*

| Parameter | Type   | Description                  | Required |
|-----------|--------|------------------------------|----------|
| id        | integer| The ID of the product        | Yes      |

*Response:*

- *Status Code:* 200 OK if the product is found.
 *Status Code:* 404 Not Found if the product is not found.

*Response Body:*

json
{
  "id": 1,
  "name": "Sample Product",
  "description": "This is a sample product.",
  "price": 19.99,
  "quantity": 100
}


*Error Response Body (if product is not found):*

json
{
  "error": "Product not found"
}


#### 4. Update Product

*URL:* /api/products/<int:id>

*Method:* PUT

*Description:* Updates the details of a specific product by its ID.

*URL Parameter:*

| Parameter | Type   | Description                  | Required |
|-----------|--------|------------------------------|----------|
| id        | integer| The ID of the product        | Yes      |

*Request Body:*

| Field       | Type    | Description                | Required |
|-------------|---------|----------------------------|----------|
| name        | string  | The name of the product    | Yes      |
| description | string  | A short description        | No       |
| price       | number  | The price of the product   | Yes      |
| quantity    | integer | The stock quantity         | Yes      |

*Request Example:*

json
{
  "name": "Updated Product",
  "description": "This is an updated product.",
  "price": 29.99,
  "quantity": 50
}


*Response:*

- *Status Code:* 200 OK

*Response Body:*

json
{
  "message": "Product updated successfully"
}

#### 5. Delete Product

*URL:* /api/products/<int:id>

*Method:* DELETE

*Description:* Deletes a specific product by its ID.

*URL Parameter:*

| Parameter | Type   | Description                  | Required |
|-----------|--------|------------------------------|----------|
| id        | integer| The ID of the product        | Yes      |

*Response:*

- *Status Code:* 200 OK

*Response Body:*

json
{
  "message": "Product deleted successfully"
}


#### 6. Create Razorpay Order

*URL:* /api/create_order

*Method:* POST

*Description:* Creates a Razorpay order for a product.
*Request Body:*

| Field       | Type    | Description                | Required |
|-------------|---------|----------------------------|----------|
| product_id  | integer | The ID of the product      | Yes      |
| quantity    | integer | The quantity to purchase   | Yes      |

*Request Example:*

json
{
  "product_id": 1,
  "quantity": 2
}


*Response:*

- *Status Code:* 200 OK

*Response Body:*

json
{
  "id": "order_id",
  "amount": 3998,
  "currency": "INR",
  "status": "created"
}


#### 7. Handle Payment Success

*URL:* /api/payment_success
Method:* POST

*Description:* Handles the successful payment from Razorpay.

*Request Body:*

| Field                | Type    | Description                | Required |
|----------------------|---------|----------------------------|----------|
| razorpay_order_id    | string  | The Razorpay order ID      | Yes      |
| razorpay_payment_id  | string  | The Razorpay payment ID    | Yes      |
| razorpay_signature   | string  | The Razorpay signature     | Yes      |

*Request Example:*

json
{
  "razorpay_order_id": "order_id",
  "razorpay_payment_id": "payment_id",
  "razorpay_signature": "signature"
}


*Response:*

- *Status Code:* 200 OK

*Response Body:*

json
{
  "message": "Payment successful"
}
Error Response Body (if signature verification fails):*

json
{
  "error": "Signature verification failed"
}


### Environment Variables

| Variable            | Description                             | Default Value     |
|---------------------|-----------------------------------------|-------------------|
| MYSQL_HOST          | The hostname of the MySQL server        | localhost         |
| MYSQL_USER          | The MySQL user                          | root              |
| MYSQL_PASSWORD      | The password for the MySQL user         | MYSQL_PASSWORD    |
| MYSQL_DB            | The MySQL database name                 | ecommerce_db      |
| RAZORPAY_KEY_ID     | The Razorpay API key ID                 | RAZORPAY_KEY_ID   |
| RAZORPAY_KEY_SECRET | The Razorpay API key secret             | RAZORPAY_KEY_SECRET|

### Testing with Postman

You can also test the backend API using Postman. Here's how:

1. Open Postman and create new requests for each API endpoint.
2. Set up the environment variables in Postman to match your backend configuration.
3. Send requests to the appropriate endpoints to test their functionality.

### Example Request

sh
curl -X POST http://localhost:5000/api/products \
    -H "Content-Type: application/json" \
    -d '{"name": "Sample Product", "description": "This is a sample product.", "price": 19.99, "quantity": 100}'
---

This updated README reflects the current state and capabilities of your Flask application, providing clear instructions for setup, configuration, and API usage.
