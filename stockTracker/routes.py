import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from flask_login import login_user, current_user, logout_user, login_required
from stockTracker import app, db, bcrypt
from stockTracker.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
    TransactionForm, SecurityForm, RequestResetForm, ResetPasswordForm)
from stockTracker.models import User, Security, Transaction



@app.route("/")
@app.route("/home")
def home():
    if current_user.is_authenticated:
        page = request.args.get('page', 1, type=int)
        securities = Security.query.filter_by(user_id=current_user.id)\
            .order_by(Security.date_posted.desc()).paginate(page=page, per_page=20)
        return render_template('home.html', securities = securities)
    else:
        return render_template('home.html')



@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)


@app.route("/create/security", methods=['GET', 'POST'])
@login_required
def new_security():
    form = SecurityForm()
    if form.validate_on_submit():
        security = Security(title=form.title.data, author=current_user, date_posted=form.date.data)
        db.session.add(security)
        db.session.commit()
        flash('A security has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_security.html', title='Create Security',\
        form=form, legend='New Security')


@app.route("/security/<string:security_title>")
@login_required
def security(security_title):
        try:
            security = Security.query.filter_by(user_id=current_user.id, title=security_title).first()
        except AttributeError:
            abort(404)
        if security == None:
            abort(404)
        transactions = Transaction.query.filter_by(security_id=security.id)\
            .order_by(Transaction.date_posted.desc(), Transaction.id.desc())
        return render_template('security.html', title=security.title, security=security,\
            transactions=transactions)


@app.route("/security/<string:security_title>/delete", methods=['POST'])
@login_required
def delete_security(security_title):
    try:
        security = Security.query.filter_by(user_id=current_user.id, title=security_title).first()
    except AttributeError:
        abort(404)
    if security == None:
        abort(404)
    if security.author != current_user:
        about(403)
    db.session.delete(security)
    db.session.commit()
    flash('Your security has been deleted!', 'success')
    return redirect(url_for('home'))


@app.route("/security/<string:security_title>/update", methods=['GET', 'POST'])
@login_required
def update_security(security_title):
    try:
        security = Security.query.filter_by(user_id=current_user.id, title=security_title).first()
    except AttributeError:
        abort(404)
    if security == None:
        abort(404)
    if security.author != current_user:
        about(403)
    form = SecurityForm()
    form.updateCheck = 1
    if form.validate_on_submit():
        security.title = form.title.data
        security.date_posted = form.date.data
        db.session.commit()
        flash('Your security has been updated!', 'success')
        return redirect(url_for('security', security_title=security.title))
    elif request.method == 'GET':
        form.title.data = security.title
        form.date.data = security.date_posted
    return render_template('create_security.html', title='Update Security', form=form, legend='Update Post')


@app.route("/create/transaction", methods=['GET', 'POST'])
@login_required
def new_transaction():
    securities=db.session.query(Security).filter(Security.user_id == current_user.id).all()
    #Now forming the list of tuples for SelectField
    securityList=[(i.title, i.title) for i in securities]
    #passing group_list to the form
    form = TransactionForm()
    form.security.choices = securityList
    if form.validate_on_submit():
        security_id = Security.query.filter_by(title=form.security.data, user_id=current_user.id).first().id
        transaction = Transaction(security_id=security_id, transaction_type=form.transaction_type.data,\
            date_posted=form.date.data, price=form.price.data, shares=form.shares.data)
        db.session.add(transaction)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('security', security_title=form.security.data))
    return render_template('create_transaction.html', title='Create Transaction',\
        form=form, legend='New Transaction')