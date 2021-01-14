import datetime

from flask import Flask, render_template, request, url_for, redirect, flash, \
    session, abort
from flask_sqlalchemy import sqlalchemy, SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Change dbname here
db_name = "auth.db"

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{db}'.format(db=db_name)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SECRET_KEY required for session, flash and Flask Sqlalchemy to work
app.config['SECRET_KEY'] = '25FE82FDBX177gytd'

db = SQLAlchemy(app)


class User(db.Model):
    """
    Model class that handles the DB User table
    """
    uid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    pass_hash = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return self.username


class Todo(db.Model):
    """
    Model class that handles the DB Todo table
    """
    uid = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(500), unique=False, nullable=False)
    status = db.Column(db.Boolean(), nullable=False, default=True)
    user_uid = db.Column(db.Integer, db.ForeignKey('user.uid'), nullable=False)
    user = db.relationship('User', backref=db.backref('todos', lazy=True))
    date = db.Column(db.Date(), nullable=False)

    def __repr__(self):
        return self.title


def create_db():
    """ # Execute this first time to create new db in current directory. """
    db.create_all()


@app.route("/signup/", methods=["POST"])
def signup():
    """
    Implements signup functionality. Allows username and password for new user.
    Hashes password with salt using werkzeug.security.
    Stores username and hashed password inside database.
    Username should to be unique else raises sqlalchemy.exc.IntegrityError.
    """

    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        if not (username and password):
            flash("Username or Password cannot be empty")
            return redirect(url_for('signup'))
        else:
            username = username.strip()
            password = password.strip()

        # Returns salted pwd hash in format : method$salt$hashcode
        hashed_pwd = generate_password_hash(password, 'sha256')

        new_user = User(username=username, pass_hash=hashed_pwd)
        db.session.add(new_user)

        try:
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            flash("Username {u} is not available.".format(u=username))
            return redirect(url_for('signup'))

        flash("User account has been created.")
        return render_template("user_home.html", username=username)


@app.route("/", methods=["GET"])
def index():
    """Landing page """
    return render_template("index.html")


@app.route("/login/", methods=["GET", "POST"])
def login():
    """
    Provides login functionality by rendering login form on get request.
    On post checks password hash from db for given input username and password.
    If hash matches redirects authorized user to home page else redirect to
    login page with error message.
    """

    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        if not (username and password):
            flash("Username or Password cannot be empty.")
            return redirect(url_for('index'))
        else:
            username = username.strip()
            password = password.strip()

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.pass_hash, password):
            session[username] = True
            return redirect(url_for("user_home", username=username))
        else:
            flash("Invalid username or password.")
            return redirect(url_for('index'))


@app.route("/user/<username>/", methods=["GET"])
def user_home(username):
    """
    Home page for validated users.
    """
    user = User.query.filter_by(username=username).first()
    # Get all the todos for the registered used
    todos = Todo.query.filter_by(user_uid=user.uid)
    # if the user is not logged abort
    if not session.get(username):
        abort(401)

    return render_template("user_home.html", username=username, todos=todos)


@app.route("/user/<username>/addtodo/", methods=['POST'])
def addtodo(username):
    """    Add a new todo    """
    user = User.query.filter_by(username=username).first()

    title = request.form['title']
    new_todo = Todo(title=title, status=False, date=datetime.datetime.now(), user_uid=user.uid, user=user)
    db.session.add(new_todo)

    db.session.commit()
    user = User.query.filter_by(username=username).first()

    todos = Todo.query.filter_by(user_uid=user.uid)
    return redirect(url_for('user_home', username=username))


@app.route('/user/<username>/complete/<uid>', methods=['POST'])
def completetodo(username, uid):
    """  Complete a specific todo    """

    todo = Todo.query.filter_by(uid=uid).first()
    todo.status = True
    db.session.commit()
    return redirect(url_for('user_home', username=username))


@app.route('/user/<username>/uncomplete/<uid>', methods=['POST'])
def uncompletetodo(username, uid):
    """   Uncomplete a specific todo    """

    todo = Todo.query.filter_by(uid=uid).first()
    todo.status = False
    db.session.commit()
    return redirect(url_for('user_home', username=username))


@app.route('/user/<username>/remove/<uid>', methods=['POST'])
def removetodo(username, uid):
    """   Remove  a specific todo    """

    Todo.query.filter_by(uid=uid).delete()
    db.session.commit()
    return redirect(url_for('user_home', username=username))


@app.route("/logout/<username>")
def logout(username):
    """ Logout user and redirect to login page with success message."""
    session.pop(username, None)
    flash("successfully logged out.")
    return redirect(url_for('index'))


if __name__ == "__main__":
    # print(db)
    # create_db()
    app.run(debug=True, host='0.0.0.0')
