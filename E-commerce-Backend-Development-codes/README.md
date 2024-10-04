# E-commerce Merchandise Website Project

This branch contains the code for an e-commerce merchandise website built using MongoDB and Python Flask. The project is organized into 5 main tasks, each representing a week's worth of progress.

## Project Structure
# E-commerce Merchandise Website Project

## Project Structure

ecommerce-merch-website/
├── week1-database-and-server-setup/
│   ├── models.py
│   ├── db_config.py
│   └── server.py
├── week2-payment-integration/
│   ├── razorpay_integration.py
│   └── payment_routes.py
├── week3-mongodb-migration-and-core-endpoints/
│   ├── mongodb_migration.py
│   ├── login_routes.py
│   ├── cart_routes.py
│   ├── wishlist_routes.py
│   └── tag_routes.py
├── week4-endpoint-development/
│   ├── product_routes.py
│   ├── user_routes.py
│   ├── order_routes.py
│   └── review_routes.py
├── week5-development-and-documentation/
│   ├── api_documentation.md
│   └── test_cases.py
├── app.py
├── requirements.txt
└── README.md

## Weekly Task Objectives

1. **Week 1: Database and Server Setup**
   - Set up necessary databases
   - Implement APIs
   - Develop server-side logic to support merchandise functionalities

2. **Week 2: Payment Gateway Integration**
   - Integrate Razorpay Payment Gateway with the backend

3. **Week 3: MongoDB Migration and Core Endpoints**
   - Migrate the current database to MongoDB
   - Develop endpoints for:
     * Login
     * Cart
     * Wishlist
     * Tags
     * Other necessary core functionalities

4. **Week 4: Comprehensive Endpoint Development**
   - Develop all remaining endpoints
   - Ensure consistency with the current UI design

5. **Week 5: Endpoint Development and Documentation**
   - Complete backend development
   - Create documentation according to the given Figma designs

## Getting Started

1. Clone the repository:
git clone https://github.com/yourusername/ecommerce-merch-website.git
cd ecommerce-merch-website

2. Install the required dependencies:
pip install -r requirements.txt

3. Set up your MongoDB connection in `week1-database-and-server-setup/db_config.py`.

4. Configure Razorpay API keys in `week2-payment-integration/razorpay_integration.py`.

5. Run the application:
python app.py

## License

This project is licensed under the MIT License - see the LICENSE file for details.
