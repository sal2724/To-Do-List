import logging
import re
from flask import Flask, flash, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy 
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

app = Flask(__name__)

# Create a custom logger
logger = logging.getLogger(__name__)
  
logging.basicConfig(filename='file.log', encoding='utf-8', level=logging.DEBUG, filemode='w', format="%(asctime)s - %(levelname)s - %(message)s")

bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqldb://root:1234@localhost/todolist'
engine = create_engine('mysql+mysqldb://root:1234@localhost/todolist')
Session = sessionmaker(bind=engine)
dbsession = Session()


db = SQLAlchemy(app)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200))
    complete = db.Column(db.Boolean)

class Accounts(db.Model):
    __tablename__ = 'accounts'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(350), nullable=False)
    email = db.Column(db.String(100), nullable=False)

app.secret_key = 'your secret key'
users = {} 

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

@app.route('/')
def index():
    is_logged_in = session.get('loggedin')
    if (is_logged_in is None or is_logged_in is False):
        return redirect("/login")
    incomplete = Todo.query.filter_by(complete=False).all()
    complete = Todo.query.filter_by(complete=True).all()

    return render_template('index.html', incomplete=incomplete, complete=complete)

@app.route('/add', methods=['POST'])
def add():
    todo = Todo(text=request.form['todoitem'], complete=False)
    db.session.add(todo)
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/complete/<id>')
def complete(id):

    todo = Todo.query.filter_by(id=int(id)).first()
    todo.complete = True
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/login', methods =['GET', 'POST'])
def login():
    logger.info("Started Login")
    if (request.method == "GET"):
        return render_template("login.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return render_template("login.html", msg = "Incorrect username / password !")
        
        # Query for f'SELECT * FROM accounts WHERE username = "{username}"')).fetchone()
        account = dbsession.query(Accounts).filter_by(username = username).one_or_none()
        if not account:
            flash(f'Incorrect username / password !', 'error')
            return render_template("login.html")
        correct_password = bcrypt.check_password_hash(account.password, password  )
        if not correct_password:
            logger.error("Incorrect password")
            flash(f'Incorrect username / password !', 'error')
            return render_template("login.html")
        else:
            session['loggedin'] = True
            session['id'] = account.id
            session['username'] = account.username
            flash(f'Welcome, {username}! You have successfully logged in.')
            return redirect("/")

@app.route('/logout', methods =['GET', 'POST'])
def logout():
        logger.info("User is logged out")
        session.clear()
        return redirect("/login")

    

@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form :
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        hashed_password = bcrypt.generate_password_hash(password.encode())
        users[username] = {'password': hashed_password}
        
        desired_username = {username}
        # Query for SELECT * FROM accounts WHERE username = "{username}"
        account = dbsession.query(Accounts).filter(Accounts.username == desired_username).all() 

        if account:
            msg = 'Account already exists !'
            logger.warning("Account already exists !")
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
            logger.error("Invalid email address !")
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
            logger.warning("Username must contain only characters and numbers !")
        elif not username or not password or not email:
            msg = 'Please fill out the form !'
            logger.warning("Please fill out the form !")
        else:
            

            #Query for INSERT INTO accounts VALUES (NULL, "{username}","{hashed_password.decode()}", "{email}"
            new_account = Accounts(username=username, password=hashed_password.decode(), email=email)
            # Add the new Account object to the session
            dbsession.add(new_account)

            # Commit the transaction to save the new record to the database
            dbsession.commit()

            msg = "You have successfully  registered"
            logger.info("New user has registered")
            flash(f'Welcome, {username}! You have successfully  registered')
            return redirect("/login")

    elif request.method == 'POST':
        msg = 'Please fill out the form !'

    return render_template("register.html", msg = msg)



if __name__ == '__main__':
    app.run(debug=True)