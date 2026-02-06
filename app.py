from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_bcrypt import Bcrypt

# -------------------------
# APP CONFIG
# -------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "pixelforge-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///pixelforge.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# -------------------------
# MODELS
# -------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # admin / lead / developer


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    deadline = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default="Active")  # Active / Completed


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------------
# ROUTES
# -------------------------
@app.route("/")
def home():
    return redirect(url_for("login"))


import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_bcrypt import Bcrypt

# -------------------------
# APP CONFIG
# -------------------------
app = Flask(__name__)
# Security: Using an environment variable for the secret key is a best practice
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "pixelforge-nexus-ultra-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///pixelforge.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# -------------------------
# MODELS
# -------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # admin / lead / developer

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    deadline = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default="Active")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------
# DATABASE INITIALIZATION (CRITICAL FOR RENDER)
# -------------------------
def init_db():
    with app.app_context():
        db.create_all()
        # Automatically create admin if database is empty
        if not User.query.filter_by(username="admin").first():
            hashed_pw = bcrypt.generate_password_hash("admin123").decode("utf-8")
            admin = User(username="admin", password=hashed_pw, role="admin")
            db.session.add(admin)
            db.session.commit()
            print("Database initialized and Admin user created.")

# -------------------------
# ROUTES
# -------------------------
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    projects = Project.query.all()
    if current_user.role == "admin":
        return render_template("admin_dashboard.html", projects=projects)
    elif current_user.role == "lead":
        return render_template("lead_dashboard.html", projects=projects)
    elif current_user.role == "developer":
        return render_template("developer_dashboard.html", projects=projects)
    return "Unauthorized", 403

@app.route("/create_project", methods=["GET", "POST"])
@login_required
def create_project():
    if current_user.role != "admin":
        return "Access denied", 403

    if request.method == "POST":
        new_project = Project(
            name=request.form.get("name"),
            description=request.form.get("description"),
            deadline=request.form.get("deadline")
        )
        db.session.add(new_project)
        db.session.commit()
        flash("Project created successfully")
        return redirect(url_for("dashboard"))
    return render_template("create_project.html")

@app.route("/complete_project/<int:project_id>")
@login_required
def complete_project(project_id):
    if current_user.role != "admin":
        return "Access denied", 403
    project = Project.query.get_or_404(project_id)
    project.status = "Completed"
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# -------------------------
# MAIN EXECUTION
# -------------------------
if __name__ == "__main__":
    init_db()
    # Render uses port 10000 by default, local uses 5000
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)