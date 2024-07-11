from app import app, db, bcrypt
from models import User, Admin, Doctor, Patient, Appointment
from datetime import datetime

with app.app_context():
    # Drop existing tables
    db.drop_all()
    # Create tables
    db.create_all()

    # Clear session
    db.session.remove()

    # Create some users with dummy passwords
    user1 = User(user_name='alice', role='patient')
    user1.password_hash = "patient1" 
    user2 = User(user_name='bob', role='doctor')
    user2.password_hash = "doctor1"
    user3 = User(user_name='charlie', role='admin')
    user3.password_hash = "admin123"

    # Create an admin
    admin1 = Admin(user=user3)

    # Create some doctors
    doctor1 = Doctor(name='Dr. Smith', specialization='Cardiology', user=user2)
    doctor2 = Doctor(name='Dr. Johnson', specialization='Neurology', user=user2)

    # Create some patients
    patient1 = Patient(name='Alice Johnson', age=29, gender='Female', user=user1)
    patient2 = Patient(name='Bob Smith', age=45, gender='Male', user=user1)

    # Create some appointments
    appointment1 = Appointment(date=datetime(2023, 7, 9, 10, 0), doctor=doctor1, patient=patient1)
    appointment2 = Appointment(date=datetime(2023, 7, 10, 11, 0), doctor=doctor2, patient=patient2)

    # Add the records to the session and commit them to the database
    db.session.add_all([user1, user2, user3, admin1, doctor1, doctor2, patient1, patient2, appointment1, appointment2])
    db.session.commit()

    print("Database seeded!")
