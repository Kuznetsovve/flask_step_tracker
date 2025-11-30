from datetime import datetime
from flask import Flask, render_template
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_login import LoginManager, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from config import Config

app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = Config.SQLALCHEMY_DATABASE_URI
app.secret_key = Config.secret_key
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 
    
db = SQLAlchemy(app)


class User(db.Model, UserMixin): 
    __tablename__ = 'user'

    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    steps = db.relationship("Steps", back_populates="user")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Steps(db.Model):
    __tablename__ = 'steps'

    id = db.Column(db.Integer, primary_key=True)
    datetime = db.Column(db.DateTime(), default=datetime.utcnow)
    steps = db.Column(db.Integer, nullable=False)  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', back_populates='steps')


class RegistrationForm(FlaskForm):
    username = StringField('Логин', validators=[
        DataRequired(message="Логин обязателен"),
        Length(min=3, max=50, message="Логин от 3 до 50 символов")
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(message="Пароль обязателен"),
        Length(min=4, message="Пароль минимум 4 символов")
    ])
    password_confirm = PasswordField('Подтвердите пароль', validators=[
        DataRequired(message="Подтверждение пароля обязательно"),
        EqualTo('password', message="Пароли не совпадают")
    ])
    submit = SubmitField("Зарегистрироваться")


class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запомнить')
    submit = SubmitField("Войти")


with app.app_context():
    db.create_all()

@app.route('/', methods= ['GET', 'POST'])
def home_page():
    return render_template(template_name_or_list="home_page.html")

@app.route('/registration', methods= ['GET', 'POST'])
def registration():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()

    if form.validate_on_submit():
        users = User()
        users.username = form.username.data
        users.set_password(form.password.data)
        db.session.add(users)
        db.session.commit()
        flash('Регистрация прошла успешно!', 'alert-success')

        return redirect(url_for('login'))
    
    return render_template(template_name_or_list="registration.html", 
                       form=form)

@app.route('/login', methods= ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    steps = Steps.query.all()

    if form.validate_on_submit():
        user = user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data): # пароль совпал
            login_user(user)
            flash('Вход выполнен!', 'alert-success')
            return("profile")
        else:
            flash('Вход не выполнен!', 'alert-danger')

    return render_template(template_name_or_list="login.html", 
                       form=form, steps=steps)

@app.route('/profile')
@login_required
def profile():
    return render_template("profile.html")

if __name__ == '__main__':
    app.run()