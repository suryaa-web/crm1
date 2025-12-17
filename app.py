from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crm.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---- Models ----
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(200), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ---- Login loader ----
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---- Routes ----
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('customers'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('customers'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if not username or not password:
            flash('Username and password required', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'warning')
            return render_template('register.html')

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('customers'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('customers'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have logged out.', 'info')
    return redirect(url_for('login'))


# ---- Customers CRUD ----
@app.route('/customers')
@login_required
def customers():
    all_customers = Customer.query.order_by(Customer.created_at.desc()).all()
    return render_template('customers.html', customers=all_customers)


@app.route('/customers/new', methods=['GET', 'POST'])
@login_required
def new_customer():
    if request.method == 'POST':
        first = request.form['first_name'].strip()
        last = request.form['last_name'].strip()
        email = request.form['email'].strip()
        phone = request.form['phone'].strip()
        notes = request.form['notes'].strip()

        if not first:
            flash('First name is required', 'danger')
            return render_template('customer_form.html', customer=None)

        c = Customer(
            first_name=first,
            last_name=last,
            email=email,
            phone=phone,
            notes=notes
        )

        db.session.add(c)
        db.session.commit()

        flash('Customer created', 'success')
        return redirect(url_for('customers'))

    return render_template('customer_form.html', customer=None)


@app.route('/customers/<int:cust_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_customer(cust_id):
    c = Customer.query.get_or_404(cust_id)

    if request.method == 'POST':
        c.first_name = request.form['first_name'].strip()
        c.last_name = request.form['last_name'].strip()
        c.email = request.form['email'].strip()
        c.phone = request.form['phone'].strip()
        c.notes = request.form['notes'].strip()

        db.session.commit()
        flash('Customer updated', 'success')
        return redirect(url_for('customers'))

    return render_template('customer_form.html', customer=c)


@app.route('/customers/<int:cust_id>/delete', methods=['POST'])
@login_required
def delete_customer(cust_id):
    c = Customer.query.get_or_404(cust_id)
    db.session.delete(c)
    db.session.commit()
    flash('Customer deleted', 'info')
    return redirect(url_for('customers'))


# ✅ NEW ROUTES (THIS FIXES WORK & SUPPORT)
@app.route('/work')
@login_required
def work():
    return render_template('dashboard.html')


@app.route('/support')
@login_required
def support():
    return render_template('support.html')


# ---- Initialize DB if not exists ----
def init_db():
    with app.app_context():
        if not os.path.exists('crm.db'):
            db.create_all()
            print("Database created (crm.db).")


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
