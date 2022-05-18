from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import (StringField, PasswordField, SubmitField, BooleanField,
	TextAreaField, SelectField, DecimalField, IntegerField)
from wtforms.fields.html5 import DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from stockTracker.models import User, Security
from datetime import datetime


class RegistrationForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired()])
	confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Sign Up')

	def validate_username(self, username):
		user = User.query.filter_by(username=username.data).first()
		if user:
			raise ValidationError('That username is taken. Please choose a different one.')

	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user:
			raise ValidationError('That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired()])
	remember = BooleanField('Remember Me')
	submit = SubmitField('Sign Up')


class UpdateAccountForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
	email = StringField('Email', validators=[DataRequired(), Email()])
	submit = SubmitField('Update')

	def validate_username(self, username):
		if username.data != current_user.username:
			user = User.query.filter_by(username=username.data).first()
			if user:
				raise ValidationError('That username is taken. Please choose a different one.')

	def validate_email(self, email):
		if email.data != current_user.email:
			user = User.query.filter_by(email=email.data).first()
			if user:
				raise ValidationError('That email is taken. Please choose a different one.')


class SecurityForm(FlaskForm):
	updateCheck = 0
	date = DateField('Date', format='%Y-%m-%d', default=datetime.utcnow)
	title = StringField('Title', validators=[DataRequired()])
	submit = SubmitField('Add Security')

	def validate_title(self, title):
		securityCheck = Security.query.filter_by(title=title.data, user_id=current_user.id).first()
		if securityCheck and self.updateCheck==0:
			raise ValidationError('You cannot have two securities with the same title. Choose a different title.')


class TransactionForm(FlaskForm):
	security = SelectField('Security', validators=[DataRequired()])
	transaction_type = SelectField('Transaction', validators=[DataRequired()],\
		choices=[('Buy', 'Buy'), ('Sell', 'Sell')])
	date = DateField('Date', format='%Y-%m-%d', default=datetime.utcnow, validators=[DataRequired()])
	price = DecimalField('Price', places=2, rounding=None, validators=[DataRequired()])
	shares = IntegerField('Shares', validators=[DataRequired()])
	submit = SubmitField('Add Transaction')


class RequestResetForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])
	submit = SubmitField('Request Password Reset')

	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user is None:
			raise ValidationError('There is no account with no email. You must register first.')


class ResetPasswordForm(FlaskForm):
	password = PasswordField('Password', validators=[DataRequired()])
	confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Reset Password')
