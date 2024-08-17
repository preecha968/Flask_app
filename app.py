from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session management

# MongoDB configuration
app.config['MONGO_URI'] = 'mongodb://localhost:27017/flask_auth_db' 
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# MongoDB collection
users_collection = mongo.db.users

@app.route('/')
def home():
    return render_template('home.html')


#SIGNUP SYSTEM#####################################################################################
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not username or not email or not password:
            flash('Please fill out all fields')
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        if users_collection.find_one({'email': email}):
            flash('Email already registered!')
            return redirect(url_for('signup'))

        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password
        })

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('signup.html')

#LOGIN SYSTEM###############################################################################################
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users_collection.find_one({'email': email})

        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            flash('Login successful!')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password')
            return redirect(url_for('login'))

    return render_template('login.html')
#MANAGEMENT USERS###############################################################################################
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in to access the profile page.')
        return redirect(url_for('login'))
    
    users = users_collection.find({}, {"_id": 1, "username": 1, "email": 1})  # Fetch all users without displaying the MongoDB `_id`
    return render_template('profile.html', users=users)

#DELETE USERS####################################################################################################
@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    users_collection.delete_one({'_id': ObjectId(user_id)})
    flash('User deleted successfully.')
    return redirect(url_for('profile'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
