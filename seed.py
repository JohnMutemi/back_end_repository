from app import app, db
from models import User, Admin, Doctor, Patient, Appointment, Notification
from datetime import datetime

# Function to seed the database
def seed_database():
    with app.app_context():
        # Drop existing tables
        db.drop_all()
        # Create tables
        db.create_all()

        # Clear session
        db.session.remove()

        # Create some users with dummy passwords and emails
        user1 = User(user_name='alice', role='patient', email='alice@example.com')
        user1.password_hash = "patient1"
        user2 = User(user_name='bob', role='doctor', email='bob@example.com')
        user2.password_hash = "doctor1"
        user3 = User(user_name='jean', role='admin', email='jean@example.com')
        user3.password_hash = "superadmin"

        # Create an admin
        admin1 = Admin(user=user3)

        # Create some doctors
        doctor1 = Doctor(name='Dr. Smith', specialization='Cardiology', user=user2)
        doctor2 = Doctor(name='Dr. Johnson', specialization='Neurology', user=user2)

        # Create some patients
        patient1 = Patient(name='Alice Johnson', age=29, gender='Female', user=user1)
        patient2 = Patient(name='Bob Smith', age=45, gender='Male', user=user1)

        # Create some appointments
        appointment1 = Appointment(date=datetime(2023, 7, 9), time=datetime.strptime('10:00', '%H:%M').time(), doctor=doctor1, patient=patient1)
        appointment2 = Appointment(date=datetime(2023, 7, 10), time=datetime.strptime('11:00', '%H:%M').time(), doctor=doctor2, patient=patient2)

        # Create some notifications
        notification1 = Notification(type='info', message='Welcome to the system!', user=user1)
        notification2 = Notification(type='info', message='Appointment scheduled successfully.', user=user2)
        notification3 = Notification(type='info', message='Admin account created.', user=user3)

        # Add the records to the session and commit them to the database
        db.session.add_all([user1, user2, user3, admin1, doctor1, doctor2, patient1, patient2, appointment1, appointment2])
        db.session.add_all([notification1, notification2, notification3])
        db.session.commit()

        print("Database seeded successfully!")

# Run the seeding function
if __name__ == '__main__':
    seed_database()
