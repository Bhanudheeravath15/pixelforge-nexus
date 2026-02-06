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
    if current_user.role == "admin":
        projects = Project.query.all()
        return render_template(
            "admin_dashboard.html",
            projects=projects
        )

    elif current_user.role == "lead":
        return render_template("lead_dashboard.html")

    elif current_user.role == "developer":
        return render_template("developer_dashboard.html")

    return "Unauthorized access", 403


@app.route("/create_project", methods=["GET", "POST"])
@login_required
def create_project():
    if current_user.role != "admin":
        return "Access denied", 403

    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")
        deadline = request.form.get("deadline")

        project = Project(
            name=name,
            description=description,
            deadline=deadline,
        )

        db.session.add(project)
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
# TEMP ADMIN INIT (USE ONCE ON RENDER)
# -------------------------
@app.route("/init-admin")
def init_admin():
    user = User.query.filter_by(username="admin").first()
    if user:
        return "Admin already exists"

    hashed_pw = bcrypt.generate_password_hash("admin123").decode("utf-8")
    admin = User(
        username="admin",
        password=hashed_pw,
        role="admin"
    )
    db.session.add(admin)
    db.session.commit()
    return "Admin created successfully"


# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=10000)
