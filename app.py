import os
import json
from datetime import datetime, timedelta
from decimal import Decimal
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DecimalField, IntegerField, DateTimeLocalField
from wtforms.validators import DataRequired, Email, Length, Optional, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Numeric, Text, ForeignKey, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__, static_url_path='/static')
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "dev-key"),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
    WTF_CSRF_TIME_LIMIT=None
)
app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER", "static/uploads")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

DB_URL = os.getenv("DATABASE_URL", "sqlite:////var/tmp/auction.db")
engine = create_engine(DB_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="employee")
    is_active_user = Column(Boolean, default=True)
    bids = relationship("Bid", back_populates="user")
    def get_id(self): return str(self.id)

class Vehicle(Base):
    __tablename__ = "vehicles"
    id = Column(Integer, primary_key=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    year = Column(Integer, nullable=True)
    make = Column(String(100), nullable=True)
    model = Column(String(100), nullable=True)
    vin = Column(String(100), nullable=True)
    mileage = Column(Integer, nullable=True)
    starting_price = Column(Numeric(12,2), nullable=False, default=0)
    reserve_price = Column(Numeric(12,2), nullable=True)
    current_price = Column(Numeric(12,2), nullable=False, default=0)
    end_time = Column(DateTime, nullable=True)
    status = Column(String(20), default="open")
    images_json = Column(Text, default="[]")
    bids = relationship("Bid", back_populates="vehicle", order_by="Bid.amount.desc()")
    @property
    def images(self):
        try: return json.loads(self.images_json or "[]")
        except Exception: return []
    @images.setter
    def images(self, val): self.images_json = json.dumps(val or [])

class Bid(Base):
    __tablename__ = "bids"
    id = Column(Integer, primary_key=True)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Numeric(12,2), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    vehicle = relationship("Vehicle", back_populates="bids")
    user = relationship("User", back_populates="bids")

Base.metadata.create_all(engine)

def seed_admin():
    session = SessionLocal()
    admin_email = os.getenv("ADMIN_EMAIL", "admin@yourcompany.com").lower()
    admin_pwd = os.getenv("ADMIN_PASSWORD", "ChangeMe123!")
    existing = session.query(User).filter_by(email=admin_email).first()
    if not existing:
        u = User(name="Admin", email=admin_email, password_hash=generate_password_hash(admin_pwd), role="admin")
        session.add(u); session.commit()
    session.close()
seed_admin()

@login_manager.user_loader
def load_user(user_id):
    session = SessionLocal()
    u = session.get(User, int(user_id))
    session.close()
    return u

class RegisterForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired(), Length(max=120)])
    email = StringField("Company Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Create Account")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class VehicleForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=200)])
    description = TextAreaField("Description", validators=[Optional()])
    year = IntegerField("Year", validators=[Optional()])
    make = StringField("Make", validators=[Optional(), Length(max=100)])
    model = StringField("Model", validators=[Optional(), Length(max=100)])
    vin = StringField("VIN", validators=[Optional(), Length(max=100)])
    mileage = IntegerField("Mileage", validators=[Optional()])
    starting_price = DecimalField("Starting Price", validators=[DataRequired(), NumberRange(min=0)])
    reserve_price = DecimalField("Reserve Price (optional)", validators=[Optional()])
    end_time = DateTimeLocalField("End Time", format="%Y-%m-%dT%H:%M", validators=[Optional()])
    submit = SubmitField("Save")

class BidForm(FlaskForm):
    amount = DecimalField("Your Bid", validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField("Place Bid")

def admin_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return f(*a, **k)
    return wrapper

def get_session(): return SessionLocal()

@app.route("/")
def index():
    session = get_session()
    now = datetime.utcnow()
    for v in session.query(Vehicle).filter(Vehicle.status=="open", Vehicle.end_time != None, Vehicle.end_time < now).all():
        v.status = "closed"
        top = session.query(Bid).filter_by(vehicle_id=v.id).order_by(Bid.amount.desc()).first()
        if top and (v.reserve_price is None or top.amount >= v.reserve_price):
            v.status = "sold"; v.current_price = top.amount
        else:
            v.status = "unsold"
    session.commit()
    vehicles = session.query(Vehicle).order_by(Vehicle.status.asc(), Vehicle.end_time.asc().nulls_last()).all()
    session.close()
    return render_template("index.html", vehicles=vehicles)

@app.route("/vehicle/<int:vehicle_id>", methods=["GET", "POST"])
def vehicle_detail(vehicle_id):
    session = get_session()
    v = session.get(Vehicle, vehicle_id)
    if not v: session.close(); abort(404)
    form = BidForm()
    min_next = Decimal(v.current_price or v.starting_price or 0) + Decimal("1.00")
    error = None
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Please log in to bid.", "warning")
            session.close()
            return redirect(url_for("login", next=url_for("vehicle_detail", vehicle_id=v.id)))
        amount = Decimal(form.amount.data).quantize(Decimal("0.01"))
        baseline = Decimal(v.current_price if v.current_price else v.starting_price)
        if amount < baseline + Decimal("1.00"):
            error = f"Bid must be at least ${baseline + Decimal('1.00'):.2f}."
        elif v.status != "open":
            error = "Auction is not open."
        else:
            if v.end_time and (v.end_time - datetime.utcnow()) <= timedelta(minutes=1):
                v.end_time = v.end_time + timedelta(minutes=2)
            bid = Bid(vehicle_id=v.id, user_id=current_user.id, amount=amount)
            v.current_price = amount
            session.add(bid); session.commit()
            flash("Bid placed!", "success")
            session.close()
            return redirect(url_for("vehicle_detail", vehicle_id=v.id))
    top = session.query(Bid).filter_by(vehicle_id=v.id).order_by(Bid.amount.desc()).first()
    bids = session.query(Bid).filter_by(vehicle_id=v.id).order_by(Bid.amount.desc()).all()
    session.close()
    return render_template("vehicle.html", v=v, bids=bids, top_bid=top, form=form, min_next=min_next, error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        session = get_session()
        if session.query(User).filter_by(email=form.email.data.lower()).first():
            flash("Email already registered.", "danger")
            session.close(); return redirect(url_for("login"))
        u = User(name=form.name.data.strip(), email=form.email.data.lower(),
                 password_hash=generate_password_hash(form.password.data), role="employee")
        session.add(u); session.commit(); session.close()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session = get_session()
        u = session.query(User).filter_by(email=form.email.data.lower()).first()
        if u and check_password_hash(u.password_hash, form.password.data) and u.is_active_user:
            login_user(u)
            session.close()
            flash("Welcome back!", "success")
            nxt = request.args.get("next")
            return redirect(nxt or url_for("index"))
        session.close()
        flash("Invalid credentials or inactive account.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

@app.route("/admin")
@login_required
@admin_required
def admin_home():
    session = get_session()
    vehicles = session.query(Vehicle).order_by(Vehicle.id.desc()).all()
    users = session.query(User).order_by(User.id.desc()).all()
    session.close()
    return render_template("admin.html", vehicles=vehicles, users=users)

@app.template_filter()
def currency(val):
    try: return "${:,.2f}".format(Decimal(val))
    except Exception: return "$0.00"

@app.context_processor
def inject_now(): return {"now": datetime.utcnow()}

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
