from flask import Flask, jsonify, request, abort
from pymongo import MongoClient
from bson import SON
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os

# Load configuration
app = Flask(__name__)
app.config.from_object("config.Config")
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')  # Use environment variable

# Initialize MongoDB client
client = MongoClient(app.config["MONGO_URI"])
db = client.get_database()  # Get the default database from the URI

app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Collections
users_collection = db['users']
customers_collection = db['customers']
businesses_collection = db['businesses']
appointments_collection = db['appointments']

# Authentication Middleware
def token_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Authentication Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_collection.find_one({"_id": ObjectId(data['user_id'])})
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(*args, **kwargs)
    return decorated

# Signup API
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    
    # Validate input
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Email and password are required"}), 400
    
    # Check if user already exists
    existing_user = users_collection.find_one({"email": data['email']})
    if existing_user:
        return jsonify({"error": "User already exists"}), 409
    
    # Hash password
    hashed_password = generate_password_hash(data['password'])
    
    # Create user
    user_data = {
        "email": data.get('email'),
        "password": hashed_password,
        "name": data.get('name'),
        "phone": data.get('phone'),
        "created_at": datetime.datetime.utcnow()
    }
    
    user_id = users_collection.insert_one(user_data).inserted_id
    
    return jsonify({"message": "User created successfully", "user_id": str(user_id)}), 201

# Signin API
@app.route("/signin", methods=["POST"])
def signin():
    data = request.json
    is_social_login = data.get('is_social_login')
    
    # Validate input
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Email and password are required"}), 400
    
    # Find user
    user = users_collection.find_one({"email": data['email']})
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # if social login don't validate password
    # Check password
    if not is_social_login  and not check_password_hash(user['password'], data['password']):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Generate token
    token = jwt.encode({
        'user_id': str(user['_id']),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        "message": "Login successful", 
        "token": token,
        "user_id": str(user['_id'])
    }), 200

# Customer List API
@app.route("/customers", methods=["GET"])
@token_required
def get_customers():
    customer_id = request.args.get('customer_id')
    customers = list(customers_collection.find({customer_id : customer_id}))
    for customer in customers:
        customer['_id'] = str(customer['_id'])
    return jsonify(customers), 200

# Add Customer API
@app.route("/customers", methods=["POST"])
@token_required
def add_customer():
    data = request.json
    
    # Validate input
    if not data or not data.get('name') or not data.get('phone'):
        return jsonify({"error": "Name and phone are required"}), 400
    
    # Check if customer already exists
    existing_customer = customers_collection.find_one({"phone": data['phone']})
    if existing_customer:
        return jsonify({"error": "Customer already exists"}), 409
    
    customer_data = {
        "customer_id": data['customer_id'],
        "name": data['name'],
        "phone": data.get('phone', ''),
        "created_at": datetime.datetime.utcnow()
    }
    
    customer_id = customers_collection.insert_one(customer_data).inserted_id
    
    return jsonify({
        "message": "Customer added successfully", 
        "customer_id": str(customer_id)
    }), 201

# Edit Customer API
@app.route("/customers/<customer_id>", methods=["PUT"])
@token_required
def edit_customer(customer_id):
    data = request.json
    
    try:
        customer_object_id = ObjectId(customer_id)
    except:
        return jsonify({"error": "Invalid customer ID"}), 400
    
    # Find customer
    customer = customers_collection.find_one({"_id": customer_object_id})
    if not customer:
        return jsonify({"error": "Customer not found"}), 404
    
    # Update customer
    update_data = {k: v for k, v in data.items() if k in ['name', 'phone', 'time']}
    
    customers_collection.update_one(
        {"_id": customer_object_id},
        {"$set": update_data}
    )
    
    return jsonify({"message": "Customer updated successfully"}), 200

# Add Appointment API
@app.route("/appointments", methods=["POST"])
@token_required
def add_appointment():
    data = request.json
    
    # Validate input
    if not data or not data.get('customer_id') or not data.get('date'):
        return jsonify({"error": "Customer ID and date are required"}), 400
    
    try:
        customer_object_id = ObjectId(data['customer_id'])
    except:
        return jsonify({"error": "Invalid customer ID"}), 400
    
    # Check if customer exists
    customer = customers_collection.find_one({"_id": customer_object_id})
    if not customer:
        return jsonify({"error": "Customer not found"}), 404
    
    appointment_data = {
        "customer_id": customer_object_id,
        "date": data['date'],
        "time": data.get('time', ''),
        "category": data.get('category', ''),
        "location": data.get('location', ''),
        "status": data.get('status', 'scheduled'),
        "created_at": datetime.datetime.utcnow()
    }
    
    appointment_id = appointments_collection.insert_one(appointment_data).inserted_id
    
    return jsonify({
        "message": "Appointment added successfully", 
        "appointment_id": str(appointment_id)
    }), 201

# Get Appointments List API
@app.route("/appointments", methods=["GET"])
@token_required
def get_appointments():
    customer_id = request.args.get('customer_id')
    appointments = list(appointments_collection.find({customer_id: customer_id}))
    
    # Convert ObjectId to string and include customer details
    for appointment in appointments:
        appointment['_id'] = str(appointment['_id'])

    return jsonify(appointments), 200

# Create Business API
@app.route("/businesses", methods=["POST"])
@token_required
def create_business():
    data = request.json
    # Validate input
    if not data or not data.get('name'):
        return jsonify({"error": "Business name is required"}), 400
    
    # Check if business already exists
    existing_business = businesses_collection.find_one({"name": data['name']})
    if existing_business:
        return jsonify({"error": "Business already exists"}), 409
    
    business_data = {
        "customer_id" : data['customer_id'],
        "name": data['name'],
        "image": data['image'],
        "category": data.get('category', ''),
        "address": data.get('address', ''),
        "phone": data.get('phone', ''),
        "created_at": datetime.datetime.utcnow()
    }
    
    business_id = businesses_collection.insert_one(business_data).inserted_id
    
    return jsonify({
        "message": "Business created successfully", 
        "business_id": str(business_id)
    }), 201
# Get Businesses List API
@app.route("/businesses", methods=["GET"])
@token_required
def get_businesses():
    customer_id = request.args.get('customer_id')
    businesses = list(businesses_collection.find({customer_id : customer_id}))
    
    # Convert ObjectId to string and include customer details
    for businesse in businesses:
        businesse['_id'] = str(businesse['_id'])

    return jsonify(businesses), 200

# Home route
@app.route("/")
def home():
    return jsonify({"message": "Welcome to the Booking System API!"})

@app.route('/upload/images', methods=['POST'])
def upload_images():
    if 'files' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    
    files = request.files.getlist('files')
    
    if not files or files[0].filename == '':
        return jsonify({'message': 'No selected file'}), 400
    
    uploaded_files = []
    for file in files:
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            uploaded_files.append(filename)
    
    return jsonify({
        'message': f'Successfully uploaded {len(uploaded_files)} file(s)',
        'file': filename
    }), 200

# Run the app
if __name__ == "__main__":
    app.run(debug=True, port=5000, host="0.0.0.0")