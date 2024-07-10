#!/usr/bin/env python3
import os
from flask import Flask, request, make_response, session, jsonify
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api, Resource
from flask_bcrypt import Bcrypt

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///models.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact=False
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)

api = Api(app)
from models import db, Doctor, Patient, Appointment, User
db.init_app(app)
migrate = Migrate(app, db)

@app.before_request
def check_login():
    user_id = session.get('user_id')
    if user_id is None\
        and request.endpoint != 'index'\
        and request.endpoint != 'login'\
        and request.endpoint != 'logout'\
        and request.endpoint != 'register' \
        and request.endpoint != 'check_session':
        return{"error":"unauthorized access"},401
# Resources
class Login(Resource):
    def post(self):
        data = request.get_json()
        user_name = data['user_name']
        password = data['password']
        
        user = User.query.filter_by(user_name=user_name).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            welcome_message = f"Welcome {user.user_name}"
            return {
                'message': welcome_message,
                'id': user.id,
                'user_name': user.user_name,
                'role': user.role
            }, 200

        return {"error": "Invalid username or password"}, 401

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


# Index Resource
class Index(Resource):
  
    # Returns a welcome message for the Patient-Doctor Appointment System.
    def get(self):
        response_dict = {
            "message": "Welcome to the Patient-Doctor Appointment System!"
        }
        response = make_response(response_dict, 200)
        return response

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
  
#     Updates details of a specific patient by ID
    def get(self, patient_id):
        patient = Patient.query.get(patient_id)
        if patient:
            response_dict = patient.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Patient not found"}, 404)
        return response

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
#  Deletes a specific patient by ID.
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
    
    #  Returns a list of all appointments.
    def get(self):
        response_dict_list = [appointment.to_dict() for appointment in Appointment.query.all()]
        response = make_response(response_dict_list, 200)
        return response
#  Adds a new appointment.
    def post(self):
        
        new_appointment = Appointment(
            doctor_id=request.form('doctor_id'),
            patient_id=request.form('patient_id'),
            date=request.form.get('date'),
            time=request.form.get('time')
        )
        db.session.add(new_appointment)
        db.session.commit()
        response_dict = new_appointment.to_dict()
        response = make_response(response_dict, 201)
        return response

# AppointmentByID Resource
class AppointmentByID(Resource):
    
#  Retrieves details of a specific appointment by ID.
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
            appointment.doctor_id = data.get('doctor_id', appointment.doctor_id)
            appointment.patient_id = data.get('patient_id', appointment.patient_id)
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
    
# Add resources to API
api.add_resource(Register, '/register', endpoint='register')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(CheckSession, '/check_session', endpoint='check-session')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(Index, '/', endpoint='index')
api.add_resource(Doctors, '/doctors', endpoint='doctors')
api.add_resource(DoctorByID, '/doctors/<int:doctor_id>')
api.add_resource(Patients, '/patients', endpoint='patients')
api.add_resource(PatientByID, '/patients/<int:patient_id>')
api.add_resource(Appointments, '/appointments', endpoint='appointments')
api.add_resource(AppointmentByID, '/appointments/<int:appointment_id>')

if __name__ == '__main__':
    app.run(port=5555, debug=True)