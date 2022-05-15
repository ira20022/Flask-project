from email import message
from pyexpat.errors import messages
from flask import Flask,render_template,redirect,flash,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,UserMixin
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed,FileField
from requests import request, session
from wtforms import StringField,PasswordField,SubmitField,BooleanField,IntegerField
from wtforms.validators import DataRequired,Length,Email,EqualTo,ValidationError
from flask_bcrypt import Bcrypt
import bcrypt
from flask_login import login_user,current_user,logout_user,login_required
from flask_login import UserMixin
from flask_login import LoginManager
import sqlite3
from datetime import datetime
from sqlalchemy import or_
app=Flask(__name__)

#for login
login_manager=LoginManager(app)
login_manager.login_view='login'
login_manager.login_message_category='info'

#for database
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///users.db'
app.config['SECRET_KEY']='thisissecret'

db=SQLAlchemy(app)
bcrypt=Bcrypt(app)

# login_manager=LoginManager()
# login_manager.init_app(app)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(20),unique=True,nullable=False)
    email=db.Column(db.String(120),unique=True,nullable=False)
    password=db.Column(db.String(60),nullable=False)
    transactions=db.relationship('Transaction',backref='user',lazy='dynamic')

    # def __init__(self,username,email,password):
    #     self.username=username
    #     self.email=email
    #     self.password=password

class Transaction(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    borrower_name=db.Column(db.String(200),nullable=False)
    amt=db.Column(db.Integer,nullable=True)
    desc=db.Column(db.String(200),nullable=False)
    date_created=db.Column(db.DateTime,default=datetime.utcnow)
    settlement=db.Column(db.Boolean,default=False,nullable=False)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'))
    # def __init__(self,owner_name,borrower_name,amt,desc,settlement):
    #     self.owner_name=owner_name
    #     self.settlement=settlement
    #     self.borrower_name=borrower_name
    #     self.amt=amt
    #     self.desc=desc
    #     self.settlement=settlement




class RegistrationForm(FlaskForm):
    username=StringField('Enter Username', validators=[DataRequired(),Length(min=2,max=20)])
    email=StringField('Enter Email',validators=[DataRequired(),Email()])
    password=PasswordField('Enter Password',validators=[DataRequired()])
    confirm_password=PasswordField('Confirm Password',validators=[DataRequired(),EqualTo('password')])
    submit=SubmitField('Sign Up')

    def validate_username(self,username):

        user=User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose different one.')

    def validate_email(self,email):

        user=User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose different one.')

class LoginForm(FlaskForm):
    username=StringField('Enter Username',validators=[DataRequired(),Length(min=2,max=20)])
    password=PasswordField('Enter Password',validators=[DataRequired()])
    remember=BooleanField('Remember Me')
    submit=SubmitField('Login')

class TransactionForm(FlaskForm):
    amount=IntegerField('Enter the Amount',validators=[DataRequired()])
    desc=StringField('Enter the item name',validators=[DataRequired()])
    submit=SubmitField('ADD FRIENDS')


# @app.route('/')
# def login():
#     return render_template('login.html')

@app.route('/register',methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        users=User.query.all()
        # return redirect(url_for('home'),users=users)
    form=RegistrationForm()
    if form.validate_on_submit():
        hashed_pwd=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user=User(username=form.username.data, email=form.email.data, password=hashed_pwd)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!','success')
        return redirect(url_for('login'))
    return render_template('regis.html',form=form)


@app.route('/',methods=['POST','GET'])
def login():
    if current_user.is_authenticated:
        # form=TransactionForm()
        # return redirect(url_for('userpage',username=current_user.username))
        # return redirect(url_for('userpage'))
        return render_template('UserPage.html',name=current_user.username)
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user,remember=form.remember.data)
            name=form.username.data
            # form=TransactionForm()
            # return redirect(url_for('userpage',curr_user=current_user))
            return redirect(url_for('userpage',username=name))
            # return render_template('UserPage.html',name=name)
            # return redirect(url_for('userpage',name=name,allusers=allusers))
        else:
            flash("Login Unsuccessful. Please check the email and password")
    return  render_template('login.html',title='Login',form=form)

@app.route('/UserPage/<string:username>',methods=['POST','GET'])
@login_required
def userpage(username):
    form=TransactionForm()
    if form.validate_on_submit():
        amount=form.amount.data
        desc=form.desc.data
        # userfriends=User.query.filter(User.username!=current_user.username)
        # return render_template('Friends.html',name=current_user.username,amount=amount,desc=desc,userfriends=userfriends)
        return redirect(url_for('friends',amount=amount,desc=desc,len=0))

    return render_template('UserPage.html',name=username,form=form)


@app.route('/Friend/<int:amount>/<string:desc>/<int:len>',methods=['POST','GET'])
@login_required
def friends(amount,desc,len):
    userfriends=User.query.filter(User.username!=current_user.username)
    return render_template('Friends.html',userfriends=userfriends,name=current_user.username,amount=amount,desc=desc,len=len)

ids=[]
@app.route('/Selectfriends/<int:amount>/<string:desc>/<int:id>')
@login_required
def selectfriends(amount,desc,id):
    ids.append(id)
    return redirect(url_for('friends',amount=amount,desc=desc,len=len(ids)))

@app.route('/Addfriend/<int:amount>/<string:desc>')
@login_required
def addfriend(amount,desc):
    amt=amount/(len(ids)+1)
    for i in range(len(ids)):
        borr=User.query.filter_by(id=ids[i]).first()
        t=Transaction(borrower_name=borr.username,amt=amt,desc=desc,settlement=False,user=current_user)
        db.session.add(t)
        db.session.commit()
    ids.clear()
    return redirect(url_for('dashboard',username=current_user.username))
    trans=Transaction.query.filter(or_(Transaction.borrower_name==current_user.username,Transaction.user_id==current_user.id))
    return render_template('Dashboard.html',trans=trans)

@app.route('/Dashboard/<string:username>')
@login_required
def dashboard(username):
    trans=Transaction.query.filter(or_(Transaction.borrower_name==current_user.username,Transaction.user_id==current_user.id))
    return render_template('Dashboard.html',trans=trans)

@app.route('/Dashboard/<int:id>')
@login_required
def settletrans(id):
    tran_del=Transaction.query.get(id)
    db.session.delete(tran_del)
    db.session.commit()
    return redirect(url_for('dashboard',username=current_user.username))



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__=='__main__':
    app.run(debug=True)