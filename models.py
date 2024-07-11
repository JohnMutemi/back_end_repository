from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from sqlalchemy.orm import validates
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.ext.hybrid import hybrid_property
from app import bcrypt
from datetime import datetime

metadata = MetaData(naming_convention={
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"
})
db = SQLAlchemy(metadata=metadata)

# models
class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(64), nullable=False, unique=True)
    _password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin', 'doctor', 'patient'

    doctor = db.relationship('Doctor', uselist=False, back_populates='user')
    patient = db.relationship('Patient', uselist=False, back_populates='user')
    admin = db.relationship('Admin', uselist=False, back_populates='user')
    notifications = db.relationship('Notification', back_populates='user')
    serialize_rules = ('-doctor.user', '-patient.user', '-admin.user')

    def __repr__(self):
        return f'User {self.user_name}'

    @hybrid_property
    def password_hash(self):
        return self._password_hash

    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    @validates('user_name')
    def validate_user_name(self, key, user_name):
        if not user_name:
            raise ValueError("User name cannot be empty")
        return user_name

    @validates('_password_hash')
    def validate_password_hash(self, key, password_hash):
        if not password_hash:
            raise ValueError("Password hash cannot be empty")
        return password_hash

    @validates('role')
    def validate_role(self, key, role):
        if role not in ['admin', 'doctor', 'patient']:
            raise ValueError("Role must be one of 'admin', 'doctor', or 'patient'")
        return role

    def set_password(self, password):
        self.password_hash = password

    def to_dict(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'role': self.role
        }


class Doctor(db.Model, SerializerMixin):
    __tablename__ = 'doctors'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    user = db.relationship('User', back_populates='doctor')
    appointments = db.relationship('Appointment', back_populates='doctor', cascade='all, delete-orphan')

    serialize_rules = ('-appointments.doctor', '-user')

    def __repr__(self):
        return f'<Doctor {self.id}, {self.name}, {self.specialization}>'

class Patient(db.Model, SerializerMixin):
    __tablename__ = 'patients'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    user = db.relationship('User', back_populates='patient')
    appointments = db.relationship('Appointment', back_populates='patient', cascade='all, delete-orphan')

    serialize_rules = ('-appointments.patient', '-user')

    def __repr__(self):
        return f'<Patient {self.id}, {self.name}, {self.age}, {self.gender}>'

class Appointment(db.Model, SerializerMixin):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)

    doctor = db.relationship('Doctor', back_populates='appointments')
    patient = db.relationship('Patient', back_populates='appointments')

    serialize_rules = ('-doctor.appointments', '-patient.appointments')

    def __repr__(self):
        return f'<Appointment {self.id}, {self.date}>'
class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', back_populates='notifications')

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "message": self.message,
            "created_at": self.created_at.isoformat(),
            "user_id": self.user_id
        }

class Admin(db.Model, SerializerMixin):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    user = db.relationship('User', back_populates='admin')

    serialize_rules = ('-user',)

    def __repr__(self):
        return f'<Admin {self.id}>'