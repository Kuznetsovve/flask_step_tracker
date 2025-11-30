from datetime import datetime, timedelta
from flask import Flask, render_template
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from wtforms import StringField, SubmitField, PasswordField, BooleanField, IntegerField
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


class StepsForm(FlaskForm):
    steps = IntegerField('Шаги', validators=[DataRequired()])
    submit = SubmitField("Сохранить")


with app.app_context():
    db.create_all()

@app.route('/', methods= ['GET', 'POST'])
def home_page():
    return render_template(template_name_or_list="home_page.html")

@app.route('/registration', methods= ['GET', 'POST'])
def registration():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    form = RegistrationForm()

    if form.validate_on_submit():
        users = User()
        users.username = form.username.data
        users.set_password(form.password.data)
        db.session.add(users)
        db.session.commit()
        flash('Регистрация прошла успешно!', 'alert-success')

        return redirect(url_for('add_steps'))
    
    return render_template(template_name_or_list="registration.html", 
                       form=form)

@app.route('/login', methods= ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    
    form = LoginForm()
    steps = Steps.query.all()

    if form.validate_on_submit():
        user = user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data): # пароль совпал
            login_user(user)
            flash('Вход выполнен!', 'alert-success')
            return redirect(url_for('profile'))
        else:
            flash('Вход не выполнен!', 'alert-danger')

    return render_template(template_name_or_list="login.html", 
                       form=form, steps=steps)

@app.route('/add_steps', methods=['GET', 'POST'])
@login_required
def add_steps():
    form = StepsForm()
    if form.validate_on_submit():
        step = Steps(steps=form.steps.data, user_id=current_user.id)
        db.session.add(step)
        db.session.commit()
        flash('Шаги сохранены!', 'alert-success')
        return redirect(url_for('profile'))
    return render_template('add_steps.html', form=form)

@app.route('/profile')
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route('/me')
@login_required
def me():
    user_steps = Steps.query.filter_by(user_id=current_user.id).all()
    return render_template('me.html', steps=user_steps, user=current_user)

@app.route('/me/weeek')
@login_required
def weeek_stats():
    today = datetime.utcnow()
    week_start = today - timedelta(days=today.weekday(), weeks=0)
    week_end = week_start + timedelta(days=6)
    avg_steps = db.session.query(func.avg(Steps.steps)).filter(
        Steps.user_id == current_user.id,
        Steps.datetime >= week_start,
        Steps.datetime <= week_end
    ).scalar() or 0
    return render_template('stats.html', avg=avg_steps, period='Текущая неделя')

@app.route('/me/weeek/<int:n>')
@login_required
def weeek_n_stats(n):
    year_start = datetime(datetime.now().year, 1, 1)
    week_start = year_start + timedelta(weeks=n-1)
    week_end = week_start + timedelta(days=6)
    avg_steps = db.session.query(func.avg(Steps.steps)).filter(
        Steps.user_id == current_user.id,
        Steps.datetime >= week_start,
        Steps.datetime <= week_end
    ).scalar() or 0
    return render_template('stats.html', avg=avg_steps, period=f'Неделя {n}')

@app.route('/me/month')
@login_required
def month_stats():
    today = datetime.utcnow()
    avg_steps = db.session.query(func.avg(Steps.steps)).filter(
        Steps.user_id == current_user.id,
        func.extract('year', Steps.datetime) == today.year,
        func.extract('month', Steps.datetime) == today.month
    ).scalar() or 0
    return render_template('stats.html', avg=avg_steps, period='Текущий месяц')

@app.route('/me/month/<int:n>')
@login_required
def month_n_stats(n):
    avg_steps = db.session.query(func.avg(Steps.steps)).filter(
        Steps.user_id == current_user.id,
        func.extract('month', Steps.datetime) == n
    ).scalar() or 0
    return render_template('stats.html', avg=avg_steps, period=f'Месяц {n}')

from datetime import datetime
from sqlalchemy import func

@app.route('/me/quarter')
@login_required
def quarter_stats():
    today = datetime.utcnow()
    quarter = (today.month - 1) // 3 + 1

    avg_steps = db.session.query(func.avg(Steps.steps)).filter(
        Steps.user_id == current_user.id,
        func.extract('year', Steps.datetime) == today.year,
        ((func.extract('month', Steps.datetime) - 1) // 3 + 1) == quarter
    ).scalar() or 0

    return render_template('stats.html', avg=avg_steps, period='Текущий квартал')

@app.route('/me/quarter/<int:n>')
@login_required
def quarter_n_stats(n):
    if n < 1 or n > 4:
        flash('Квартал должен быть от 1 до 4', 'alert-danger')
        return redirect(url_for('profile'))

    today = datetime.utcnow()
    year = today.year

    avg_steps = db.session.query(func.avg(Steps.steps)).filter(
        Steps.user_id == current_user.id,
        func.extract('year', Steps.datetime) == year,
        ((func.extract('month', Steps.datetime) - 1) // 3 + 1) == n
    ).scalar() or 0

    return render_template('stats.html', avg=avg_steps, period=f'Квартал {n} {year} года')

@app.route('/me/year')
@login_required
def year_stats():
    today = datetime.utcnow()

    avg_steps = db.session.query(func.avg(Steps.steps)).filter(
        Steps.user_id == current_user.id,
        func.extract('year', Steps.datetime) == today.year
    ).scalar() or 0

    return render_template('stats.html', avg=avg_steps, period='Текущий год')

@app.route('/me/year/<int:n>')
@login_required
def year_n_stats(n):
    year = n

    avg_steps = db.session.query(func.avg(Steps.steps)).filter(
        Steps.user_id == current_user.id,
        func.extract('year', Steps.datetime) == year
    ).scalar() or 0

    return render_template('stats.html', avg=avg_steps, period=f'Год {year}')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home_page'))

if __name__ == '__main__':
    app.run()