#!/usr/bin/env python3
import random
from flask import Flask, request, make_response, session, jsonify, redirect, url_for
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api, Resource
from werkzeug.exceptions import NotFound
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from datetime import timedelta

app = Flask(__name__)
# CORS(app)
CORS(app, supports_credentials=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
# CORS(app, supports_credentials=True, origins=["http://localhost:3000"])
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///models.db"  # Use postgres in production
app.config["JWT_SECRET_KEY"] = "fsbdgfnhgvjnvhmvh" + str(random.randint(1, 1000000000000))
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SECRET_KEY"] = "JKSRVHJVFBSRDFV" + str(random.randint(1, 1000000000000))
app.json.compact = False

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
load_dotenv()

api = Api(app)

from models import db, Doctor, Patient, Appointment, User
db.init_app(app)
migrate = Migrate(app, db)

@app.errorhandler(NotFound)
def handle_not_found(e):
    response = make_response(
        jsonify({'error': 'NotFound', 'message': 'The requested resource does not exist'}),
        404
    )
    response.headers['Content-Type'] = 'application/json'
    return response

app.register_error_handler(404, handle_not_found)

@app.route('/sessions/<string:key>', methods=['GET'])
def show_cookies(key):
    session['username'] = session.get('username') or 'jack_daniels'
    session_value = session.get(key, 'Key not found')
    response = make_response(jsonify({
        'session': {
            'session_key': key,
            'session_value': session_value,
            'session_access': session.accessed,
        },
        'cookie': [{cookie: request.cookies[cookie]}
                   for cookie in request.cookies], }), 200)
    response.set_cookie('cookie_name', 'cookie')
    return response

@app.before_request
def check_login():
    allowed_endpoints = ['login', 'logout', 'register', 'session']

    if request.endpoint in allowed_endpoints:
        return

    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access. Please log in."}), 401

    user_id = session['user_id']
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "User not found. Please log in again."}), 401

    if request.endpoint == 'doctors':
        return

    if request.endpoint == 'patients':
        if user.role not in ['admin', 'doctor']:
            return jsonify({"error": "Unauthorized access. Admin or Doctor role required."}), 403

    request.user = user

class Login(Resource):
    def post(self):
        user_name = request.form.get('user_name')
        password = request.form.get('password')

        user = User.query.filter_by(user_name=user_name).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            access_token = create_access_token(identity=user.id)
            return {
                'message': f"Welcome {user.user_name}",
                'access_token': access_token,
                'user_name': user.user_name,
                'role': user.role,
                'email': user.email
            }, 200
        else:
            return {"error": "Invalid username or password"}, 401

class Register(Resource):
    def post(self):
        user_name = request.form.get('user_name')
        password = request.form.get('password')
        role = request.form.get('role')
        email = request.form.get('email')

        if not user_name or not password or not role or not email:
            return {'message': 'Username, password, role, and email are required'}, 400

        if role not in ['admin', 'doctor', 'patient']:
            return {'message': 'Invalid role specified'}, 400

        if User.query.filter_by(user_name=user_name).first():
            return {'message': 'User already exists'}, 400

        new_user = User(user_name=user_name, role=role, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        success_message = {'message': 'User registered successfully'}
        response = make_response(success_message)
        response.status_code = 201
        response.headers['Location'] = url_for('login')

        return response

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
    
class UserProfileResource(Resource):
    def get(self, user_id=None):
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
            return {'error': 'User not found'}, 404
        users = User.query.all()
        return [user.to_dict() for user in users], 200

    def put(self, user_id):
        data = request.get_json()
        user = User.query.get(user_id)
        if user:
            user.user_name = data['user_name']
            user.email = data['email']
            user.role = data['role']
            if 'password' in data:
                user.password = data['password']
            db.session.commit()
            return user.to_dict(), 200
        return {'error': 'User not found'}, 404

class Doctors(Resource):
    def get(self):
        response_dict_list = [doctor.to_dict() for doctor in Doctor.query.all()]
        response = make_response(response_dict_list, 200)
        return response

    def post(self):
        name = request.form.get('name')
        specialization = request.form.get('specialization')
        if not name or not specialization:
            return {"error": "Name and specialization are required"}, 400

        new_doctor = Doctor(name=name, specialization=specialization)
        db.session.add(new_doctor)
        db.session.commit()
        response_dict = new_doctor.to_dict()
        response = make_response(response_dict, 201)
        return response

class DoctorByID(Resource):
    def get(self, doctor_id):
        doctor = Doctor.query.get(doctor_id)
        if doctor:
            response_dict = doctor.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Doctor not found"}, 404)
        return response

    def put(self, doctor_id):
        doctor = Doctor.query.get(doctor_id)
        if doctor:
            doctor.name = request.form.get('name', doctor.name)
            doctor.specialization = request.form.get('specialization', doctor.specialization)
            db.session.commit()
            response_dict = doctor.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Doctor not found"}, 404)
        return response

    def delete(self, doctor_id):
        doctor = Doctor.query.get(doctor_id)
        if doctor:
            db.session.delete(doctor)
            db.session.commit()
            response = make_response({"message": "Doctor deleted successfully"}, 200)
        else:
            response = make_response({"error": "Doctor not found"}, 404)
        return response

class Patients(Resource):
    def get(self):
        response_dict_list = [patient.to_dict() for patient in Patient.query.all()]
        response = make_response(response_dict_list, 200)
        return response

    def post(self):
        name = request.form.get('name')
        age = request.form.get('age')
        gender = request.form.get('gender')
        if not name or not age or not gender:
            return {"error": "Name, age, and gender are required"}, 400

        new_patient = Patient(name=name, age=age, gender=gender)
        db.session.add(new_patient)
        db.session.commit()
        response_dict = new_patient.to_dict()
        response = make_response(response_dict, 201)
        return response

class PatientByID(Resource):
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
            patient.name = request.form.get('name', patient.name)
            patient.age = request.form.get('age', patient.age)
            patient.gender = request.form.get('gender', patient.gender)
            db.session.commit()
            response_dict = patient.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Patient not found"}, 404)
        return response

    def delete(self, patient_id):
        patient = Patient.query.get(patient_id)
        if patient:
            db.session.delete(patient)
            db.session.commit()
            response = make_response({"message": "Patient deleted successfully"}, 200)
        else:
            response = make_response({"error": "Patient not found"}, 404)
        return response

class Appointments(Resource):
    def get(self):
        response_dict_list = [appointment.to_dict() for appointment in Appointment.query.all()]
        response = make_response(response_dict_list, 200)
        return response

    def post(self):
        doctor_id = request.form.get('doctor_id')
        patient_id = request.form.get('patient_id')
        date = request.form.get('date')
        time = request.form.get('time')

        doctor = Doctor.query.get(doctor_id)
        patient = Patient.query.get(patient_id)

        if not doctor or not patient:
            return {"error": "Invalid doctor or patient ID"}, 400

        if not date or not time:
            return {"error": "Date and time are required"}, 400

        new_appointment = Appointment(doctor=doctor, patient=patient, date=date, time=time)
        db.session.add(new_appointment)
        db.session.commit()
        response_dict = new_appointment.to_dict()
        response = make_response(response_dict, 201)
        return response

class AppointmentByID(Resource):
    def get(self, appointment_id):
        appointment = Appointment.query.get(appointment_id)
        if appointment:
            response_dict = appointment.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Appointment not found"}, 404)
        return response

    def put(self, appointment_id):
        appointment = Appointment.query.get(appointment_id)
        if appointment:
            appointment.doctor_id = request.form.get('doctor_id', appointment.doctor_id)
            appointment.patient_id = request.form.get('patient_id', appointment.patient_id)
            appointment.date = request.form.get('date', appointment.date)
            appointment.time = request.form.get('time', appointment.time)
            db.session.commit()
            response_dict = appointment.to_dict()
            response = make_response(response_dict, 200)
        else:
            response = make_response({"error": "Appointment not found"}, 404)
        return response

    def delete(self, appointment_id):
        appointment = Appointment.query.get(appointment_id)
        if appointment:
            db.session.delete(appointment)
            db.session.commit()
            response = make_response({"message": "Appointment deleted successfully"}, 200)
        else:
            response = make_response({"error": "Appointment not found"}, 404)
        return response

api.add_resource(Login, '/login')
api.add_resource(Register, '/register')
api.add_resource(CheckSession, '/session')
api.add_resource(Logout, '/logout')
api.add_resource(UserProfileResource, '/profile/<int:user_id>')
api.add_resource(Doctors, '/doctors')
api.add_resource(DoctorByID, '/doctors/<int:doctor_id>')
api.add_resource(Patients, '/patients')
api.add_resource(PatientByID, '/patients/<int:patient_id>')
api.add_resource(Appointments, '/appointments')
api.add_resource(AppointmentByID, '/appointments/<int:appointment_id>')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
