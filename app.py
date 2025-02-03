from flask import Flask, jsonify, request, abort, send_from_directory
from pymongo import MongoClient
from bson import SON
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
from bson.objectid import ObjectId
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
    
    return jsonify({"message": "User created successfully", "user_id": str(user_id)}), 200

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
def get_customers():
    customer_id = request.args.get('customer_id')
    customers = list(customers_collection.find({'customer_id':customer_id}))
    for customer in customers:
        customer['_id'] = str(customer['_id'])
    return jsonify(customers), 200

# Add Customer API
@app.route("/customers", methods=["POST"])
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
def edit_customer(customer_id):
    data = request.json
    
    try:
        customer_object_id = ObjectId(customer_id)
    except Exception as e:
        print(e)
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
    # if not customer:
    #     return jsonify({"error": "Customer not found"}), 404
    
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
def get_appointments():
    customer_id = request.args.get('customer_id')
    type = request.args.get('type')
    # Fetch appointments from the MongoDB collection
    if type == "history":
        appointments = list(appointments_collection.find({'status' : 'completed'}))
    else:
        appointments = list(appointments_collection.find({'status' : 'scheduled'}))

    # Convert non-serializable fields
    for appointment in appointments:
        appointment['_id'] = str(appointment['_id'])  # Convert ObjectId to string
        appointment['customer_id'] = str(appointment['customer_id'])  # Convert ObjectId to string

    return jsonify(appointments), 200

# Create Business API
@app.route("/businesses", methods=["POST"])
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
    }), 200
# Get Businesses List API
@app.route("/businesses", methods=["GET"])
def get_businesses():
    customer_id = request.args.get('customer_id')
    businesses = list(businesses_collection.find({'customer_id' : customer_id}))
    
    # Convert ObjectId to string and include customer details
    for businesse in businesses:
        businesse['_id'] = str(businesse['_id'])

    return jsonify(businesses), 200

# Delete Client API
@app.route("/clients/<client_id>", methods=["DELETE"])
def delete_client(client_id):
    try:
        client_object_id = ObjectId(client_id)
    except Exception as e:
        return jsonify({"error": "Invalid client ID"}), 400
    
    result = customers_collection.delete_one({"_id": client_object_id})
    
    if result.deleted_count == 0:
        return jsonify({"error": "Client not found"}), 404
    
    return jsonify({"message": "Client deleted successfully"}), 200

# Delete Business API
@app.route("/businesses/<business_id>", methods=["DELETE"])
def delete_business(business_id):
    try:
        business_object_id = ObjectId(business_id)
    except Exception as e:
        return jsonify({"error": "Invalid business ID"}), 400
    
    result = businesses_collection.delete_one({"_id": business_object_id})
    
    if result.deleted_count == 0:
        return jsonify({"error": "Business not found"}), 404
    
    return jsonify({"message": "Business deleted successfully"}), 200

# Update Appointment API
@app.route("/appointments/<appointment_id>", methods=["PUT"])
def update_appointment(appointment_id):
    data = request.json
    
    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception as e:
        return jsonify({"error": "Invalid appointment ID"}), 400
    
    # Find appointment
    appointment = appointments_collection.find_one({"_id": appointment_object_id})
    if not appointment:
        return jsonify({"error": "Appointment not found"}), 404
    
    # Update appointment
    update_data = {k: v for k, v in data.items() if k in ['date', 'time', 'category', 'location', 'status']}
    
    appointments_collection.update_one(
        {"_id": appointment_object_id},
        {"$set": update_data}
    )
    
    return jsonify({"message": "Appointment updated successfully"}), 200

# Update Business API
@app.route("/businesses/<business_id>", methods=["PUT"])
def update_business(business_id):
    data = request.json
    
    try:
        business_object_id = ObjectId(business_id)
    except Exception as e:
        return jsonify({"error": "Invalid business ID"}), 400
    
    # Find business
    business = businesses_collection.find_one({"_id": business_object_id})
    if not business:
        return jsonify({"error": "Business not found"}), 404
    
    # Update business
    update_data = {k: v for k, v in data.items() if k in ['name', 'image', 'category', 'address', 'phone']}
    
    businesses_collection.update_one(
        {"_id": business_object_id},
        {"$set": update_data}
    )
    
    return jsonify({"message": "Business updated successfully"}), 200

@app.route("/completeappointment/<appointment_id>", methods=["PUT"])
def complete_appointment(appointment_id):
    data = request.json
    
    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception as e:
        return jsonify({"error": "Invalid business ID"}), 400
    
    # Find business
    appointment = appointments_collection.find_one({"_id": appointment_object_id})
    if not appointment:
        return jsonify({"error": "Business not found"}), 404
    
    # Update business
    update_data = {"status": "completed"}
    
    appointments_collection.update_one(
        {"_id": appointment_object_id},
        {"$set": update_data}
    )
    
    return jsonify({"message": "Business updated successfully"}), 200

@app.route("/appointments/<appointment_id>", methods=["DELETE"])
def delete_appointment(appointment_id):
    try:
        appointment_object_id = ObjectId(appointment_id)
    except Exception as e:
        return jsonify({"error": "Invalid appointment ID"}), 400
    
    result = appointments_collection.delete_one({"_id": appointment_object_id})
    
    if result.deleted_count == 0:
        return jsonify({"error": "Appointment not found"}), 404
    
    return jsonify({"message": "Appointment deleted successfully"}), 200
@app.route("/image/<path:filename>", methods=['GET'])
def get_image(filename):
    uploads_dir = app.config['UPLOAD_FOLDER']
    try:
        return send_from_directory(uploads_dir, filename)
    except FileNotFoundError:
        abort(404)
def home():
    return jsonify({"message": "Welcome to the Booking System API!"})

@app.route('/upload/images', methods=['POST'])
def upload_images():
    try:
        if 'files' not in request.files:
            print("No file part")
            return jsonify({'message': 'No file part'}), 400
        
        files = request.files.getlist('files')
        print(files)
        if not files or files[0].filename == '':
            print("No selected file")
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
    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred'}), 500
    

# Update User Information API
@app.route("/users/<user_id>", methods=["PUT"])
def update_user_data(user_id):
    try:
        user_object_id = ObjectId(user_id)
    except Exception as e:
        return jsonify({"error": "Invalid user ID"}), 400
    
    # Get the updated data from the request
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Update user information
    result = users_collection.update_one({"_id": user_object_id}, {"$set": data})
    
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({"message": "User information updated successfully"}), 200

@app.route("/users/<user_id>", methods=["GET"])
def get_user_data(user_id):
    try:
        user_object_id = ObjectId(user_id)
    except Exception as e:
        return jsonify({"error": "Invalid user ID"}), 400
    
    user = users_collection.find_one({"_id": user_object_id})
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    user['_id'] = str(user['_id'])  # Convert ObjectId to string
    return jsonify(user), 200

if __name__ == "__main__":
    app.run(debug=True, port=5005, host="0.0.0.0")
