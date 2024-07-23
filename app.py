from flask import Flask,render_template,request,url_for,redirect,session,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,LoginManager,login_user, login_required, logout_user, current_user
from datetime import datetime,timezone
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import abort
from datetime import timedelta

app = Flask(__name__)
app.secret_key="pappytus"
app.permanent_session_lifetime = timedelta(days= 1)

db = SQLAlchemy()
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db.init_app(app)
app.app_context().push()       

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  
        return f(*args, **kwargs)
    return decorated_function

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True )
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique = True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  
    role = db.Column(db.String(50), nullable=False, default='user')

class security_logs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(tz=timezone.utc))

class Visitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    meeting = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(tz=timezone.utc))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/user",methods=["POST","GET"])
@login_required
@admin_required
def user():
        if request.method =="POST":
            visitorName = request.form["name"]
            visitorPhone = request.form["phone"]
            meeting = request.form["meeting"]
            newVisitor = Visitor(name=visitorName,phone=visitorPhone,meeting=meeting)
            flash("Added Successfully", category="info")
            db.session.add(newVisitor)
            db.session.commit()
            return redirect(url_for("user"))
        recent_visitors = Visitor.query.order_by(Visitor.timestamp.desc()).limit(10).all()
        return render_template("user.html", current_user=current_user, recent_visitors=recent_visitors)
        
    
@app.route("/login" , methods =["POST","GET"])
def login():
    if request.method == "POST":
        username=request.form["username"]
        loginPassword=request.form["password"]
        user= User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password,loginPassword):
            login_user(user)
            new_log = security_logs(username=username, action="login")
            db.session.add(new_log)
            db.session.commit()
            session["user"]=username
            return redirect(url_for("user")) 
        else:
            flash("Invalid credentials","error")
            return render_template("login.html")
    else:
        return render_template("login.html")    
    

@app.route("/register",methods=["POST","GET"])
def RegisterUser():
    if request.method == "POST":
        registerUserName = request.form["username"]
        registerPassword = request.form["password"]
        registeremail = request.form["email"]
        hashPasssword = generate_password_hash(registerPassword)
        newUser = User(username=registerUserName,password=hashPasssword,email=registeremail)
        db.session.add(newUser)
        db.session.commit()
        login_user(newUser)
        return redirect(url_for("user"))   
    return render_template("RegisterUser.html")

@app.route("/logout")
@login_required
def logout():
    username = current_user.username
    logout_user()
    session.pop("user", None)
    new_log = security_logs(username=username, action="logout")
    db.session.add(new_log)
    db.session.commit()
    return redirect(url_for("home"))

if __name__ =="__main__":
    app.run(debug=True)