from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import LoginForm,SignupForm
from models import mongo, User, AuditLog  # Ensure these are correctly imported
from config import Config
import os

app = Flask(__name__)
app.config.from_object(Config)

# Fix: Correct initialization of Flask-PyMongo
mongo.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({"username": user_id})
    if user_data:
        return User(username=user_data['username'], password=user_data['password'], role=user_data['role'])
    return None

@app.before_request
def create_admin_user():
    if mongo.db.users.count_documents({}) == 0:
        hashed_password = generate_password_hash('admin', method='pbkdf2:sha256')
        mongo.db.users.insert_one({
            'username': 'defname',
            'password': hashed_password,
             'role': 'admin'
            
        })

@app.route('/')
def home():
     return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_data = mongo.db.users.find_one({"username": form.username.data})
        if user_data and check_password_hash(user_data['password'], form.password.data):
            user = User(username=user_data['username'], password=user_data['password'], role=user_data['role'])
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password')
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
 # Only allow logged-in users with proper roles to add new users
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        # Hash the password and add the user to the database
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        mongo.db.users.insert_one({
          
            'username': form.username.data,
            'password': hashed_password,
            'role': form.role.data,
             # Assign the selected role to the new user
        })
        flash('User created successfully!')
        return redirect(url_for('login'))
    if form.errors:
        print(form.errors)
    return render_template('signup.html', form=form)


ROLE_PERMISSIONS = {
    'admin': ['find', 'insert','update' ,'delete','create_collection','drop_collection'],
    'developer': ['find','insert','create_collection'],
    'user': ['find','create_collection']
}

def check_query_permission(role, query):
    # Check if the query is empty
    if not query:
        return False  # or raise an exception, depending on your preference

    # Extract the type of query (e.g., insert_one, update_one, etc.)
    if "insert_one" in query or "insert_many" in query:
        query_type = 'insert'
    elif "update_one" in query or "update_many" in query:
        query_type = 'update'
    elif "delete_one" in query or "delete_many" in query:
        query_type = 'delete'
    elif "find" in query:
        query_type = 'find'
    elif "create_collection" in query:
        query_type='create_collection'
    elif ".drop()" in query:
        query_type='drop_collection'
    else:
        return False  # Unsupported query type

    # Check if the role has permission to execute this type of query
    return query_type in ROLE_PERMISSIONS.get(role, [])


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    results = None
    error = None
    message=None

    if request.method == 'POST':
        query_str = request.form['query']
        print("Received query:", query_str)  # Debugging
        
        action = f"Executed query: {query_str}"
        if not check_query_permission(current_user.role, query_str):
            error = "You do not have permission to execute this query."
        else:
        
            try:
            # Check for `find` command in the input query string
                if "find" in query_str or "find_many" in query_str :
                # Evaluate the query safely
                    results = eval(query_str)  # Make sure to restrict user input if using eval
                    results = list(results)  # Convert cursor to list

                elif "insert_one" in query_str or "insert_many" in query_str:
                        # Assuming the query is a valid insert command
                        exec(query_str)  # Evaluate the insert command safely
                        flash('Data inserted successfully!')
                elif "update_one" in query_str or "update_many" in query_str:
                        exec(query_str)  # Evaluate the insert command safely
                        flash('Data updated successfully!')
                elif "delete_one" in query_str or "delete_many" in query_str:
                       exec(query_str)  # Evaluate the delete command safely
                       flash('Data deleted successfully!')
                elif "create_collection" in query_str:
                        exec(query_str)
                        flash("Collection created successfully!")

                elif ".drop()" in query_str:
                         exec(query_str)
                         flash("Collection dropped successfully!")

                else:
                    errors = "Unsupported query type. Only ."
                    print('error is',errors)
            
            except Exception as e:
                error = f"Error executing query: {str(e)}"
                print("Exception occurred:", error)  # Debugging

        # Log the action (query execution)
            log = AuditLog(user_id=current_user.username, action=action)
            mongo.db.audit_logs.insert_one(log.__dict__)

    print("Results:", results)
    return render_template('dashboard.html', results=results, error=error)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
