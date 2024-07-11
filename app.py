#!/usr/bin/env python3
import os
from flask import Flask, request, make_response, session, render_template, jsonify
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api, Resource
from flask_bcrypt import Bcrypt

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///models.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)

api = Api(app)
from models import db, Doctor, Patient, Appointment, User
db.init_app(app)
migrate = Migrate(app, db)

# Before request handler to check login status and access permissions
def check_login():
    print(f"Endpoint: {request.endpoint}")
    print(f"Session: {session}")

    public_endpoints = ['login', 'register', 'index', 'check_session']

    # Allow public endpoints without requiring a session
    if request.endpoint in public_endpoints:
        return None

    user_id = session.get('user_id')
    user_role = session.get('role')

    if not user_id:
        return make_response({"error": "Unauthorized"}, 401)

    # Retrieve the user by ID
    user = User.query.get(user_id)
    if not user:
        return make_response({"error": "Unauthorized"}, 401)

    if user_role == 'admin':
        return None
    elif user_role == 'doctor' and request.endpoint in ['doctor', 'doctors', 'doctor_id']:
        return None
    elif user_role == 'patient' and request.endpoint in ['patient', 'patients', 'patient_id']:
        return None

    return make_response({"error": "Unauthorized"}, 401)

# Route to display home page
@app.route("/")
def index():
    return render_template('index.html')

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(user_name=data['user_name']).first()

        if user and user.authenticate(data['password']):
            session['user_id'] = user.id
            session['role'] = user.role  # Ensure the role is set
            response_dict = user.to_dict()
            response = make_response(response_dict, 200)
            print(f"Login successful: user_id={user.id}, role={user.role}")
        else:
            response = make_response({"error": "Invalid credentials"}, 401)
            print("Login failed")
        return response

class Register(Resource):
    def post(self):
        data = request.get_json()
        user_name = data['user_name']
        password = data['password']
        role = data['role']

        if not user_name or not password or not role:
            return {'message': 'Username, password, and role are required'}, 400

        if role not in ['admin', 'doctor', 'patient']:
            return {'message': 'Invalid role specified'}, 400

        if User.query.filter_by(user_name=user_name).first():
            return {'message': 'User already exists'}, 400

        new_user = User(user_name=user_name, role=role)
        new_user.set_password(password)  # Set the password using the custom method
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User registered successfully'}, 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({"error": "No active session"}), 401

        user = User.query.get(user_id)

        if user:
            return jsonify(user.to_dict()), 200
        return jsonify({"error": "User not found"}), 404

class Logout(Resource):
    def post(self):
        session.pop('user_id', None)
        session.pop('role', None)
        return jsonify({"message": "Logout successful"})

# Doctors Resource
class Doctors(Resource):
    # Returns a list of all doctors.
    def get(self):
        response_dict_list = [doctor.to_dict() for doctor in Doctor.query.all()]
        response = make_response(response_dict_list, 200)
        return response
    # Adds a new doctor.
    def post(self):
        new_doctor = Doctor(
            name=request.form.get('name'),
            specialization=request.form.get('specialization')
        )
        db.session.add(new_doctor)
        db.session.commit()
        response_dict = new_doctor.to_dict()
        response = make_response(response_dict, 201)
        return response

# DoctorByID Resource
class DoctorByID(Resource):
    # Retrieves details of a specific doctor by ID.
    def get(self, doctor_id):
        doctor = Doctor.query.get(doctor_id)
        if doctor:
            response_dict = doctor.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Doctor not found"}, 404)
        return response
    # Updates details of a specific doctor by ID.
    def put(self, doctor_id):
        doctor = Doctor.query.get(doctor_id)
        if doctor:
            data = request.get_json()
            doctor.name = data.get('name', doctor.name)
            doctor.specialization = data.get('specialization', doctor.specialization)
            db.session.commit()
            response_dict = doctor.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Doctor not found"}, 404)
        return response
    # Deletes a specific doctor by ID.
    def delete(self, doctor_id):
        doctor = Doctor.query.get(doctor_id)
        if doctor:
            db.session.delete(doctor)
            db.session.commit()
            response = make_response({"message": "Doctor deleted successfully"}, 200)
        else:
            response = make_response({"error": "Doctor not found"}, 404)
        return response

# Patients Resource
class Patients(Resource):
    # Returns a list of all patients.
    def get(self):
        response_dict_list = [patient.to_dict() for patient in Patient.query.all()]
        response = make_response(response_dict_list, 200)
        return response
    # Adds a new patient.
    def post(self):
        new_patient = Patient(
            name=request.form.get('name'),
            age=request.form.get('age'),
            gender=request.form.get('gender')
        )
        db.session.add(new_patient)
        db.session.commit()
        response_dict = new_patient.to_dict()
        response = make_response(response_dict, 201)
        return response

# PatientByID Resource
class PatientByID(Resource):
    # Retrieves details of a specific patient by ID.
    def get(self, patient_id):
        patient = Patient.query.get(patient_id)
        if patient:
            response_dict = patient.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Patient not found"}, 404)
        return response
    # Updates details of a specific patient by ID.
    def put(self, patient_id):
        patient = Patient.query.get(patient_id)
        if patient:
            data = request.get_json()
            patient.name = data.get('name', patient.name)
            patient.age = data.get('age', patient.age)
            db.session.commit()
            response_dict = patient.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Patient not found"}, 404)
        return response
    # Deletes a specific patient by ID.
    def delete(self, patient_id):
        patient = Patient.query.get(patient_id)
        if patient:
            db.session.delete(patient)
            db.session.commit()
            response = make_response({"message": "Patient deleted successfully"}, 200)
        else:
            response = make_response({"error": "Patient not found"}, 404)
        return response

# Appointments Resource
class Appointments(Resource):
    # Returns a list of all appointments.
    def get(self):
        response_dict_list = [appointment.to_dict() for appointment in Appointment.query.all()]
        response = make_response(response_dict_list, 200)
        return response
    # Adds a new appointment.
    def post(self):
        new_appointment = Appointment(
            date=request.form.get('date'),
            time=request.form.get('time'),
            doctor_id=request.form.get('doctor_id'),
            patient_id=request.form.get('patient_id')
        )
        db.session.add(new_appointment)
        db.session.commit()
        response_dict = new_appointment.to_dict()
        response = make_response(response_dict, 201)
        return response

# AppointmentByID Resource
class AppointmentByID(Resource):
    # Retrieves details of a specific appointment by ID.
    def get(self, appointment_id):
        appointment = Appointment.query.get(appointment_id)
        if appointment:
            response_dict = appointment.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Appointment not found"}, 404)
        return response
    # Updates details of a specific appointment by ID.
    def put(self, appointment_id):
        appointment = Appointment.query.get(appointment_id)
        if appointment:
            data = request.get_json()
            appointment.date = data.get('date', appointment.date)
            appointment.time = data.get('time', appointment.time)
            db.session.commit()
            response_dict = appointment.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Appointment not found"}, 404)
        return response
    # Deletes a specific appointment by ID.
    def delete(self, appointment_id):
        appointment = Appointment.query.get(appointment_id)
        if appointment:
            db.session.delete(appointment)
            db.session.commit()
            response = make_response({"message": "Appointment deleted successfully"}, 200)
        else:
            response = make_response({"error": "Appointment not found"}, 404)
        return response

# Registering the routes with the API
api.add_resource(Login, '/login')
api.add_resource(Register, '/register')
api.add_resource(CheckSession, '/check-session')
api.add_resource(Logout, '/logout')
api.add_resource(Doctors, '/doctors')
api.add_resource(DoctorByID, '/doctors/<int:doctor_id>')
api.add_resource(Patients, '/patients')
api.add_resource(PatientByID, '/patients/<int:patient_id>')
api.add_resource(Appointments, '/appointments')
api.add_resource(AppointmentByID, '/appointments/<int:appointment_id>')

if __name__ == "__main__":
    app.run(port=5000, debug=True)
