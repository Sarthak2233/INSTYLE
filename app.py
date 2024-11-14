import base64
import hashlib
import hmac
import uuid
import sys
from datetime import datetime

from dotenv import load_dotenv
# Route to generate the bill and save the image
from flask import request, render_template_string, send_file
from PIL import Image, ImageDraw, ImageFont
import io

import requests
from flask_wtf.csrf import generate_csrf
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import date, timedelta
import random
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import secrets
from PIL import Image, ImageDraw, ImageFont
import os


UPLOAD_FOLDER = 'static/uploads/'  # Define the path to the uploads folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

load_dotenv()
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
print(os.environ.get('FLASK_APP'))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('database_info')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Define the User model
class User(db.Model):

    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255))
    password = db.Column(db.String(255))
    username = db.Column(db.String(100))
    isAdmin = db.Column(db.String(10))
    payment = db.Column(db.Float, default=0)

    orders = db.relationship('Order', backref='user', cascade='all, delete-orphan')
    sales = db.relationship('Sales', backref='user', cascade='all, delete-orphan')
    reviews = db.relationship('ProductReview', backref='user', cascade='all, delete-orphan')


class Category(db.Model):
    __tablename__ = 'category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

class Merchandise(db.Model):
    __tablename__ = 'merchandise'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    image_path = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime)
    product_code = db.Column(db.String(50), nullable=False)
    size = db.Column(db.String(50))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))  # Foreign Key reference
    category = db.relationship('Category', backref='merchandise')

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('merchandise.id'))
    price = db.Column(db.Numeric(10, 2))
    purchase_date = db.Column(db.DateTime)
    quantity = db.Column(db.Integer)
    product = db.relationship('Merchandise', backref='orders')

class Sales(db.Model):
    __tablename__ = 'sales'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Foreign key reference to User table
    product_code = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    delivery_location = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now)
    phonenumber = db.Column(db.String(255), nullable=False)
    quantity = db.Column(db.Integer)

    # Define the relationship with the User table
    user_sales = db.relationship('User', backref='sales_associated')

class ProductReview(db.Model):
    __tablename__ = 'productreview'

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('merchandise.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    review_text = db.Column(db.Text, nullable=False)

    # Change the backref name to 'reviews_associated'
    user_reviews = db.relationship('User', backref='reviews_associated')

with app.app_context():
    db.create_all()

def generate_bill_image(bill_info):
    # Create a new image with a white background
    img = Image.new('RGB', (800, 600), color=(255, 255, 255))

    # Initialize the drawing context
    draw = ImageDraw.Draw(img)

    # Define font and text color
    font = ImageFont.truetype("arial.ttf", 24)
    text_color = (0, 0, 0)

    # Write bill information on the image
    draw.text((100, 100), f"Customer Name: {bill_info['customer_name']}", fill=text_color, font=font)
    draw.text((100, 150), f"Total Amount: {bill_info['total_amount']}", fill=text_color, font=font)
    # Add more text as needed

    # Save the image to the upload folder
    image_path = os.path.join(UPLOAD_FOLDER, f"{bill_info['customer_name']}_bill.png")
    img.save(image_path)

@app.route('/users')
def list_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    else:
        # Retrieve all users from the database
        user = User.query.get(session['user_id'])
        if user.isAdmin=="True":
            users = User.query.all()
            return render_template('user_list.html', users=users, user=user)
        else:
            return redirect(url_for('login'))

@app.route('/add_user',  methods=['GET', 'POST'])
def add_user():
        if 'user_id' not in session:
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if user.isAdmin=="True":
            if request.method=='POST':
                email = request.form['email']
                username = request.form['username']
                password = request.form['password']
                isAdmin = request.form['isAdmin']
                payment = float(request.form['payment'])

                new_user = User(email=email, password=password,username=username,isAdmin=isAdmin,payment=payment)

                db.session.add(new_user)
                db.session.commit()

                return redirect(url_for('list_users'))

            return render_template('add_user.html', user=user)

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
def edit_user(user_id):
    # Retrieve the user with the specified ID
    if 'user_id' not in session:
        redirect(url_for('login'))
    else:
        user = User.query.get(user_id)
        if not user:
            return 'User NotFound'
        if request.method =='POST':
            user.email = request.form['email']
            user.password = request.form['password']
            user.username = request.form['username']
            user.isAdmin = request.form['isAdmin']
            user.payment = request.form['payment']

            db.session.commit()

            return redirect(url_for('list_users'))



    # Handle form submission for editing user details
    # Update user details in the database
        return render_template('edit_user.html', user=user)

@app.route('/users/<int:user_id>/delete', methods=['POST'])
def delete_user(user_id):
    # Retrieve the user with the specified ID
    if 'user_id' not in session:
        return redirect(url_for('login'))
    else:
        user = User.query.get_or_404(user_id)
        if user:
            # Delete users from the database
            db.session.delete(user)
            db.session.commit()
        return redirect(url_for('list_users'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            error = 'Invalid username or password'
            return render_template('login.html', error=error)
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password1 = request.form['password1']
        email = request.form['email']
        isAdmin = "False"  # assuming new users are not admins by default

        # Check if the username or email already exists
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_user:
            error = 'Username already exists. Please choose a different username.'
            return render_template('signup.html', error=error)
        elif existing_email:
            error = 'Email already exists. Please use a different email.'
            return render_template('signup.html', error=error)
        else:
            if password1==password:
                # Create a new user
                if username == 'root':
                    new_user = User(username=username, password=password, email=email, isAdmin='True')
                    db.session.add(new_user)
                    db.session.commit()
                    session['user_id'] = new_user.id
                    return redirect(url_for('login'))
                else:
                    new_user = User(username=username, password=password, email=email, isAdmin=isAdmin)
                    db.session.add(new_user)
                    db.session.commit()
                    session['user_id'] = new_user.id
                    return redirect(url_for('login'))
            else:
                error = "Password doesn't match. Try again."
                return render_template('signup.html', error=error)

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/index')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    else:
        categories = Category.query.all()
        user = User.query.get(session['user_id'])

        if user.isAdmin == 'True':
            products = Merchandise.query.all()  # Fetch all products
            return render_template('index.html', user=user, products=products, categories=categories)
        else:
            return redirect(url_for('home'))





def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    print(user)
    if user.isAdmin =='True':
        if request.method == 'POST':
            product_code = request.form['pc']
            name = request.form['name']
            description = request.form['description']
            price = request.form['price']
            size = request.form['size']
            category_id = request.form['category']

            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    image_path = os.path.join('uploads', filename)
            timestamp = datetime.now()
            # Create a new product object
            new_product = Merchandise(name=name, description=description, price=price, product_code=product_code, size=size, image_path=image_path, timestamp=timestamp, category_id=category_id)
            # Add the new product to the database session
            print(new_product.image_path)
            db.session.add(new_product)
            # Commit the changes to the database
            db.session.commit()

            # Redirect to the admin index page or another appropriate page
            return redirect(url_for('index'))

    categories = Category.query.all()  # Fetch all categories
    return render_template('add_product.html', categories=categories)


@app.route('/edit_product/<int:item_id>', methods=['GET', 'POST'])
def edit_product(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    else:
        product = Merchandise.query.get(item_id)
        if not product:
            return "Product not found"  # Handle case where product doesn't exist

        if request.method == 'POST':
            # Handle form submission to edit the product
            product.product_code= request.form['product_code']
            product.name = request.form['name']
            product.description = request.form['description']
            product.price = request.form['price']
            category_id = request.form['category']

            product.category_id = category_id

            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    product.image_path = os.path.join('uploads', filename)

            # Commit the changes to the database
            db.session.commit()

            # Redirect to the admin index page or another appropriate page
            return redirect(url_for('index'))

        categories = Category.query.all()
        # If it's a GET request, render the template for editing the product
        return render_template('editmerch.html', product=product, categories=categories)

@app.route('/delete_product/<int:item_id>', methods=['POST'])
def delete_product(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    else:
        product = Merchandise.query.get(item_id)
        if product:
            db.session.delete(product)
            db.session.commit()
        return redirect(url_for('index'))


from flask import request, render_template, jsonify
def generate_chart_data(sales_data):
    # Process actual sales data to generate chart data (e.g., daily sales)
    chart_data = {}
    print(chart_data)
    for sale in sales_data:
        date_str = sale['timestamp']  # Accessing 'timestamp' key directly from dictionary
        if date_str in chart_data:
            chart_data[date_str] += sale['price'] * sale['quantity']  # Adjusted to match your data structure
        else:
            chart_data[date_str] = sale['price'] * sale['quantity']  # Adjusted to match your data structure
    return chart_data
def fetch_sales_data_from_database():
    # Query sales data from the database using SQLAlchemy
    # Replace this with your actual query to fetch sales data
    sales_data = Sales.query.all()
    return sales_data
@app.route('/sales', methods=['GET', 'POST'])
def sales():
    if 'user_id' not in session or not User.query.get(session['user_id']).isAdmin == 'True':
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user.isAdmin == 'True':
        if request.method == 'POST':
            start_date = request.json.get('start_date')
            end_date = request.json.get('end_date')
            sales_data = Sales.query.filter(Sales.timestamp.between(start_date, end_date)).all()
            print(f"THis is post {sales_data}")
            if request.is_json:
                # If request is JSON, return JSON response
                sales_json = [{'timestamp': sale.timestamp.strftime('%Y-%m-%d'),
                               'price': sale.price,
                               'username': sale.username,
                               'quantity': sale.quantity,
                               'phonenumber': sale.phonenumber,
                               'delivery_location': sale.delivery_location,
                               'product_code': sale.product_code} for sale in sales_data]
                return jsonify(sales_json)
            else:
                # If request is not JSON, render the template
                csrf_token = generate_csrf()
                return render_template('sales.html', sales_data=sales_data, csrf_token=csrf_token, user=user)

        else:
            # Handle GET request separately
            # Fetch today's sales data
            today_date = datetime.today().date()
            # Filter sales records for today's date
            sales_data = Sales.query.filter(Sales.timestamp >= today_date).all()
            print(f"This is get invoked {sales_data}")
            sales_data_serializable = []
            for sale in sales_data:
                sale_dict = {
                    'timestamp': sale.timestamp.strftime('%Y-%m-%d'),  # Convert timestamp to string
                    'price': sale.price,
                    'delivery_location':sale.delivery_location,
                    'product_code': sale.product_code,
                    'username': sale.username,
                    'phonenumber': sale.phonenumber,
                    'quantity': sale.quantity
                }
                sales_data_serializable.append(sale_dict)

            # Generate data for the chart (e.g., daily sales)
            chart_data = generate_chart_data(sales_data_serializable)
            return render_template('sales.html', chart_data=chart_data, sales_data=sales_data_serializable, csrf_token=generate_csrf(), user=user)


from collections import defaultdict

def retrieve_orders():
    # Dictionary to store orders grouped by date and customer
    grouped_orders = defaultdict(lambda: defaultdict(list))

    sales = Sales.query.all()
    for sale in sales:
        # Retrieve related user information
        user = User.query.filter_by(username=sale.username).first()
        # Retrieve related merchandise information
        merchandise = Merchandise.query.filter_by(product_code=sale.product_code).first()
        # Create a dictionary containing sale data along with related user and merchandise information
        sale_info = {
            'id': sale.id,
            'product_code': sale.product_code,
            'username': sale.username,
            'price': sale.price,
            'delivery_location': sale.delivery_location,
            'timestamp': sale.timestamp,
            'phonenumber': sale.phonenumber,
            'quantity': sale.quantity,
            'user_email': user.email if user else None,
            'user_username': user.username if user else None,
            'merchandise_name': merchandise.name if merchandise else None,
            'merchandise_description': merchandise.description if merchandise else None,
            # Add more related fields as needed
        }
        # Group orders by date and customer
        grouped_orders[sale.timestamp.date()][sale.username].append(sale_info)

    # List to store processed orders
    processed_orders = []
    # Calculate total price for each customer within a date
    for date, customer_orders in grouped_orders.items():
        for customer, orders in customer_orders.items():
            total_price = sum(order['price'] * order['quantity'] for order in orders)
            processed_orders.append({
                'date': date,
                'customer': customer,
                'orders': orders,
                'total_price': total_price
            })

    # Sort orders by the most recent date
    processed_orders.sort(key=lambda x: x['date'], reverse=True)
    return processed_orders


@app.route('/view_orders')
def view_orders():
    if 'user_id' not in session or not User.query.get(session['user_id']).isAdmin == 'True':
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    # Retrieve orders data from the database
    if user.isAdmin=="True":
        orders = retrieve_orders()  # You need to implement this function to fetch orders data
        return render_template('view_orders.html', orders=orders, user=user)


@app.route('/search_orders', methods=['GET'])
def search_orders():
    if 'user_id' not in session or not User.query.get(session['user_id']).isAdmin == 'True':
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if user.isAdmin=="True":

        search_date = request.args.get('search_date')
        filtered_orders = []

        if search_date:
            # Query the database to filter orders by the search date
            filtered_orders = Sales.query.filter(Sales.timestamp.like(f"{search_date}%")).all()
        else:
            # If no search date provided, return all orders
            filtered_orders = Sales.query.all()

        print(filtered_orders)
        # Render a partial HTML response containing only the filtered orders table
        return render_template('filtered_orders_table.html', orders=filtered_orders, date=search_date, user=user)


########################## USER SECTION ################################################from flask import request, redirect, url_for
# Define a route to serve your product images
@app.route('/<path:filename>')
def custom_static(filename):
    return send_from_directory(os.path.join(app.root_path,), filename)


@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    else:
        user = User.query.get(session['user_id'])


        if user.isAdmin == 'True':
            return redirect(url_for('index'))
        else:
            user_sales = Sales.query.filter_by(user_id=user.id).all()

            # Calculate total bill by summing up the prices of all sales
            total_bill = float(sum(sale.price * sale.quantity for sale in user_sales))
            remaining_payment = total_bill - user.payment
            products = Merchandise.query.all()
            selected_product = None
            product_id = request.args.get('product_id')
            bought_product_id = request.args.get('bought_product_id')

            if product_id:
                selected_product = next((p for p in products if p.id == int(product_id)), None)

            # Retrieve flashed message
            message = session.pop('_flashes', None)
            if message is None:
                message = [("","Happy Ordering form us."),]

            return render_template('home.html',
                                   products=products,
                                   username=user.username,
                                   product_id=product_id,
                                   bought_product_id=bought_product_id,
                                   selected_product=selected_product,
                                   message=message,
                                   remaining_payment=remaining_payment)

@app.route('/place_order', methods=['GET', 'POST'])
def place_order():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    from_category = request.args.get('from_category', False)

    if request.method == 'POST':
        user_id = session['user_id']
        product_id = request.form.get('product_id')
        price = request.form.get('price')
        quantity = request.form.get('quantity')
        purchase_date = datetime.now()



        # Validate inputs
        try:
            quantity = int(quantity)
            if quantity <= 0:
                raise ValueError("Quantity must be a positive integer")
        except ValueError:
            flash("Invalid quantity")
            return redirect(url_for('home'))

        # Process the order
        new_order = Order(user_id=user_id, product_id=product_id, price=price, quantity=quantity, purchase_date=purchase_date)
        db.session.add(new_order)
        db.session.commit()

        product_name = Merchandise.query.filter_by(id=product_id).first().name

        # Redirect based on the origin of the request
        if from_category:
            message = flash(
                f"Order placed successfully for {product_name}. Go to My Orders to check out. Else Scroll More to Shop.")
            category_id = session.get('category_id')
            return redirect(url_for('category',category_id=category_id, product_id=product_id, bought_product_id=product_id, message=message))
        else:
            flash(
                f"Order placed successfully for {product_name}. Go to My Orders to check out. Else Scroll More to Shop.")
            return redirect(url_for('home', product_id=product_id, bought_product_id=product_id))
        # redirect(url_for('home', product_id=product_id, bought_product_id=product_id))


@app.route('/my_orders')
def my_orders():
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Query orders for the current user
    user_id = session['user_id']
    user_orders = Order.query.filter_by(user_id=user_id).all()

    print(user_orders)
    # Render template and pass user_orders to it
    return render_template('myorders.html', orders=user_orders, order=user_orders[0] if user_orders else None)

@app.route('/cancel_order', methods=['POST'])
def cancel_order():
    order_id = request.form.get('order_id')
    # Here, you would write code to retrieve the order with the given order_id from the database
    # Once you have the order, you can delete it from the database or mark it as canceled
    # For demonstration purposes, let's assume you delete the order from the database
    order = Order.query.get(order_id)
    if order:
        db.session.delete(order)
        db.session.commit()

    else:
        flash("Failed to cancel order. Order not found.")
    return redirect(url_for('my_orders'))


def get_product_details(product_id):
    # Retrieve product details from the database based on product_id
    product = Merchandise.query.get(product_id)
    return product


@app.route('/product/<int:product_id>')
def show_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Fetch product details from the database
    product = get_product_details(product_id)

    # Fetch reviews for the product from the database
    reviews = ProductReview.query.filter_by(product_id=product_id).all()

    #Fetching user from database to display username
    user = User.query.get(session['user_id'])



    return render_template('productdisplay.html', product=product, reviews=reviews)



def calculate_total_bill(user_id):
    # Query all sales made by the user
    user_sales = Sales.query.filter_by(username=user_id).all()

    # Calculate total bill by summing up the prices of all sales
    total_bill = sum(sale.price * sale.quantity for sale in user_sales)

    return total_bill@app.route('/checkout', methods=['POST'])
@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        orders = Order.query.filter_by(user_id=user_id).all()

        if len(orders) == 0:
            return redirect(url_for('home'))  # Redirect to home if there are no orders

        delivery_location = request.form["delivery_location"]
        phonenumber = request.form['phonenumber']
        timestamp = datetime.now()

        total_bill = 0
        sale = None  # Initialize sale variable

        # Process each order
        for order in orders:
            product_code = order.product.product_code
            price = order.price
            quantity = order.quantity

            # Retrieve user's username
            user = User.query.get(order.user_id)
            if user:
                username = user.username
            else:
                username = "Unknown"  # or handle as per your application logic

            # Create a new Sales entry
            sale = Sales(product_code=product_code, username=username, price=price,
                         delivery_location=delivery_location, timestamp=timestamp, phonenumber=phonenumber, quantity=quantity, user_id=user_id)
            db.session.add(sale)
            total_bill += (int(price) * quantity)

            # Mark the order as processed
            order.processed = True

            # Delete the processed order
            db.session.delete(order)

        # Commit changes to the database
        db.session.commit()

        # Render a template to display the bill
        return render_template('bill.html', total_bill=total_bill, delivery_location=delivery_location,
                               phonenumber=phonenumber, sale=sale, items=orders)
    else:
        return "Invalid request"

# *************************** Esewa ***************************8
def generate_signature(message, key):
    """
    Generates HMAC-SHA256 signature and encodes it in Base64.
    """
    key = key.encode('utf-8')
    message = message.encode('utf-8')

    hmac_sha256 = hmac.new(key, message, hashlib.sha256)
    digest = hmac_sha256.digest()

    signature = base64.b64encode(digest).decode('utf-8')

    print(signature)

    return signature

@app.route('/esewa_payment', methods=['GET', 'POST'])
def esewa_prepare_payment():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    user_sales = Sales.query.filter_by(user_id=user.id).all()

    # Calculate total bill by summing up the prices of all sales
    total_bill = float(sum(sale.price * sale.quantity for sale in user_sales)) - user.payment
    print(user.payment)
    if not user:
        return "User not found", 404  # It's good practice to handle the case where the user might not exist
    if request.method == 'POST':

        amount = str(request.form['amount'])
        transaction_uuid = str(uuid.uuid4())  # This should be uniquely generated
        product_code = "EPAYTEST"

        # Generate the HMAC signature
        key = "8gBm/:&EnhH.1/q"
        message =f"{str(amount)}{transaction_uuid}EPAYTEST"
        signature = generate_signature(message, key)

        return render_template("esewa_payment.html", amount=amount, transaction_uuid=transaction_uuid,
                               product_code=product_code, signature=signature, total_bill=total_bill)
    else:
        return render_template('esewa_form.html', total_bill=total_bill)
@app.route('/esewa_payment_success')
def esew_payment_success():
    user_id = session['user_id']
    amount = request.args.get('amount')  # Ensure amount is passed back by eSewa

    user = User.query.get(user_id)
    user.payment += float(amount)
    db.session.commit()

    flash('Payment successful!')
    return redirect(url_for('home'))

@app.route('/esewa_payment_failure')
def esewa_payment_failure():
    return "Payment failed or cancelled!"

#********************************************** Khalti *****************************
@app.route('/khalti_payment', methods=['GET', 'POST'])
def khalti_prepare_payment():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    user_sales = Sales.query.filter_by(user_id=user.id).all()

    # Calculate total bill by summing up the prices of all sales
    total_bill = float(sum(sale.price * sale.quantity for sale in user_sales))
    user_payment = user.payment
    print(user.payment, total_bill)
    if not user:
        return "User not found", 404  # It's good practice to handle the case where the user might not exist
    if total_bill <= 0:
        flash('Buy something!!!')
        return redirect(url_for('home'))
    else:
        if request.method == 'POST':
            amount = str(request.form['amount'])
            transaction_uuid = str(uuid.uuid4())

            # Prepare the payload for Khalti API
            payload = {
                "return_url": url_for('khalti_payment_success', _external=True),  # Update with your actual return URL
                "website_url": request.url_root,  # Use the root URL of your website
                "amount": amount,
                "purchase_order_id": transaction_uuid,
                'purchase_order_name': 'test'
            }

            # Add your Khalti live secret key
            headers = {
                'Authorization': 'key fb8bf1b13f38491889be4676e4761fe9',
                'Content-Type': 'application/json'
            }

            # Make a POST request to Khalti API
            response = requests.post("https://a.khalti.com/api/v2/epayment/initiate/", headers=headers, json=payload)

            # Extract the response JSON
            response_json = response.json()

            # Redirect the user to the payment URL
            if 'payment_url' in response_json:
                payment_url = response_json['payment_url']
                return redirect(payment_url)
            else:
                return response_json

        else:
            return render_template('khalti_form.html', total_bill=total_bill, user_payment=user_payment)


@app.route('/khalti_payment_success')
def khalti_payment_success():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)

        if user:
            amount = request.args.get('amount')
            if amount:
                user.payment = float(amount) if user.payment is None else user.payment + float(amount)
                db.session.commit()
                flash('Payment successful!')
                return redirect(url_for('home'))
            else:
                flash('Amount not provided in request!')
                return redirect(url_for('home'))
        else:
            flash('User not found!')
            return redirect(url_for('home'))
    else:
        flash('User ID not found in session!')
        return redirect(url_for('home'))






@app.route('/save_bill_image', methods=['POST'])
def save_bill_image():
    # Get form data
    username = request.form.get('username')
    phonenumber = request.form.get('phonenumber')
    delivery_location = request.form.get('delivery_location')
    timestamp = request.form.get('timestamp')
    total_bill = request.form.get('total_bill')
    products = request.form.getlist('products[]')
    prices = request.form.getlist('prices[]')
    quantities = request.form.getlist('quantities[]')

    # Create a PIL Image object
    image = Image.new('RGB', (800, 600), color='white')
    draw = ImageDraw.Draw(image)

    # Define font and text color
    font = ImageFont.truetype("arial.ttf", 20)
    text_color = (0, 0, 0)

    # Write customer details to the image
    customer_details = f"Customer Details:\nName: {username}\nPhone Number: {phonenumber}\nDelivery Location: {delivery_location}\nDate: {timestamp}\n\n"
    draw.multiline_text((10, 10), customer_details, fill=text_color, font=font)

    # Write bill details to the image
    bill_details = "Bill Details:\n\n"
    for product, price, quantity in zip(products, prices, quantities):
        bill_details += f"Product: {product}\nPrice: {price}\nQuantity: {quantity}\n\n"
    draw.text((10, 200), bill_details, fill=text_color, font=font)

    # Calculate the height required for bill details
    bill_details_height = draw.multiline_textsize(bill_details, font=font)[1]

    # Write total bill to the image
    total_bill_text = f"Total Bill: {total_bill}"
    total_bill_width, total_bill_height = draw.textsize(total_bill_text, font=font)
    draw.text((10, 200 + bill_details_height + 20), total_bill_text, fill=text_color, font=font)

    # Save the image to a byte buffer
    img_buffer = io.BytesIO()
    image.save(img_buffer, format='PNG')
    img_buffer.seek(0)

    # Send the image file as a response
    return send_file(img_buffer, mimetype='image/png')


    # Create a PIL Image object



# Route to handle review submission
@app.route('/submit_review', methods=['POST'])
def submit_review():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        product_id = request.form.get('product_id')
        rating = request.form.get('rating')
        review_text = request.form.get('review')

        # Create a new ProductReview instance and save it to the database
        review = ProductReview(product_id=product_id, user_id=user_id, rating=rating, review_text=review_text)
        db.session.add(review)
        db.session.commit()

        flash('Review submitted successfully!', 'success')
        return redirect(url_for('show_product', product_id=product_id))

@app.route('/purchase_history')
def purchase_history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Assuming you have a user object available
    user = User.query.get(session['user_id'])
    if user:
        purchase_history = Sales.query.filter_by(username=user.username).order_by(Sales.timestamp.desc()).all()

        # Convert Sales objects to dictionaries
        purchase_history_data = []
        for sale in purchase_history:
            merchandise = Merchandise.query.filter_by(product_code=sale.product_code).first()
            sale_data = {
                'id': sale.id,
                'product_name': merchandise.name if merchandise else '',
                'product_code': sale.product_code,
                'username': sale.username,
                'price': str(sale.price),  # Convert to string to ensure JSON serializability
                'delivery_location': sale.delivery_location,
                'timestamp': sale.timestamp.strftime('%Y-%m-%d %H:%M:%S'),  # Convert to string format
                'phonenumber': sale.phonenumber,
                'quantity': sale.quantity
                # Add more fields as needed
            }
            purchase_history_data.append(sale_data)

        # Return the purchase history data as JSON
        return render_template('purchase_history.html', purchase_history=purchase_history_data)


    else:
        # Handle case where user is not logged in or authenticated
        return render_template('login.html')

@app.route('/fetch_categories')
def fetch_categories():
    # Convert each Category object to a dictionary
    categories = Category.query.all()
    categories_dict = [{'id': category.id, 'name': category.name} for category in categories]
    return jsonify(categories_dict)

@app.route('/category/<int:category_id>')
def category(category_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    else:
        user = User.query.get(session['user_id'])

        if user.isAdmin == 'True':
            return redirect(url_for('index'))
        else:
            # Fetch category details
            session['category_id'] = category_id
            category = Category.query.get(category_id)
            if category:
                # Fetch products for the selected category
                message = session.pop('_flashes', None)
                products = Merchandise.query.filter_by(category_id=category_id).all()
                return render_template('category.html', category=category, products=products, username=user.username, message=message)
            else:
                # Handle case where category does not exist
                flash("Category not found.", "error")
                return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)