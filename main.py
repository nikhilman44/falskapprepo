from flask import Flask, render_template, flash, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import login_user, logout_user, current_user, login_required, LoginManager, UserMixin
from flask_mail import Mail,Message
from itsdangerous import URLSafeTimedSerializer
from flask_bootstrap import Bootstrap
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret token'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///filesharing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'akshaypers2@gmail.com'
app.config['MAIL_PASSWORD'] = 'akshayajayria'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True



db = SQLAlchemy(app)
mail = Mail(app)
serialize = URLSafeTimedSerializer(app.config['SECRET_KEY'])
bootstrap = Bootstrap(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    files = db.relationship('Files')

    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)


class Files(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    return render_template('home.html', user=current_user)

@app.route('/uploadfile', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath) 


            new_file = Files(filename=filename, filepath=filepath)
            db.session.add(new_file)
            db.session.commit()

            return 'File uploaded successfully!'
    return render_template('home.html', user=current_user)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                flash('Login Successfully', category='success')
                login_user(user, remember=True)
                return redirect(url_for('home'))
            else:
                flash('Incorrect Password. Please Try Again.', category='error')
                return redirect(url_for('login'))
        else:
            flash('Email already exists', category='error')
            return redirect(url_for('login'))

    return render_template('login.html', user=current_user)
        

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirmPassword = request.form.get('confirmPassword')

        if len(name)<3:
            flash('Username must be atleast 3 letters', category='error')
        elif len(password) < 5:
            flash('password must be atleast 5 characters', category='error')
        elif password != confirmPassword:
            flash('password and confirmpassword did not match', category='error')
        elif len(email)<7:
            flash('Email must be atleast 7 characters', category='error')
        else:
            new_user = User(name=name, email=email, password=password)
            new_user.set_password(password)

            return redirect(url_for('verifyemail'))
        
            flash('A Confirmation email was sent to your email, Please confirm your email.', category='success')

            flash('Account created successfully.', category='success')

            # db.session.add(new_user)
            # db.session.commit()

            # login_user(new_user, remember=True)
            # return redirect(url_for('home'))
        
    return render_template('signup.html', user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/verifyemail', methods=['GET','POST'])
def verifyemail():
    to_mail = request.form.get('email')
    token = serialize.dumps(to_mail, salt='email-confirmation-key')
    msg = Message('Confirmation Email', sender='pirewaj814@edectus.com', recipients=['pirewaj814@edectus.com'])
    link = url_for('emailConfirmation', token=token, _external=True)
    msg.body = 'Your Confirmation Link' + link
    mail.send(msg)

    return redirect(url_for('emailConfirmation', token=token))

@app.route('/emailConfirmation/<token>')
def emailConfirmation():
    try:
        email = serialize.loads(token, salt='email-confirmation-key', max_age=60)
    except Exception:
        return '<h1>Link is expired </h1>'
    return 'Confirmation Done'



login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)

