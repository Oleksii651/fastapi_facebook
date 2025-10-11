from flask import *
import os
from dotenv import load_dotenv
from auth import hash_password, verify_password, create_access_token, decode_access_token
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base



load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")
app = Flask(__name__)
app.config[DATABASE_URL] = DATABASE_URL
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Message(Base):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, index=True)
    recipient = Column(String, index=True)
    content = Column(String)



@app.route('/')
def main():
    if 'access_token' in request.cookies:
        access_token = request.cookies.get('access_token')
        username = decode_access_token(access_token)
        if username:
            return render_template('main.html', username=username)
    return render_template('main.html')

@app.route('/settings', methods=['GET'])
def settings():
    access_token = request.cookies.get('access_token')
    if not access_token:
        return redirect('/login')
    
    username = decode_access_token(access_token)
    if not username:
        return redirect('/login')
    access_token = request.cookies.get('access_token')
    if not access_token:
        return redirect('/login')
    
    username = decode_access_token(access_token)
    if not username:
        return redirect('/login')
    
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    
    if not user:
        return "User not found", 404
    
    return render_template('settings.html', user=user)

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    
    hashed_password = hash_password(password)
    
    db = SessionLocal()
    new_user = User(username=username, email=email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.close()
    
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    
    if user and verify_password(password, user.hashed_password):
        access_token = create_access_token(data={"sub": user.username})
        response = make_response(redirect('/'))
        response.set_cookie('access_token', access_token)
        return response
    
    return "Invalid credentials", 401
    
@app.route('/logout')
def logout():
    response = make_response(redirect('/'))
    response.set_cookie('access_token', '', expires=0)
    return response

@app.route('/profile')
def profile():
    access_token = request.cookies.get('access_token')
    if not access_token:
        return redirect('/login')
    
    username = decode_access_token(access_token)
    if not username:
        return redirect('/login')
    
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    
    if not user:
        return "User not found", 404
    
    return render_template('profile.html', user=user)

@app.route('/delete_account', methods=['POST'])
def delete_account():
    access_token = request.cookies.get('access_token')
    if not access_token:
        return redirect('/login')
    
    username = decode_access_token(access_token)
    if not username:
        return redirect('/login')
    
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    
    if user:
        db.delete(user)
        db.commit()
    
    db.close()
    
    response = make_response(redirect('/'))
    response.set_cookie('access_token', '', expires=0)
    return response

@app.route('/update_profile', methods=['POST'])
def update_profile():
    access_token = request.cookies.get('access_token')
    if not access_token:
        return redirect('/login')
    
    username = decode_access_token(access_token)
    if not username:
        return redirect('/login')
    
    new_username = request.form['username']
    new_email = request.form['email']
    
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    
    if user:
        user.username = new_username
        user.email = new_email
        db.commit()
        db.refresh(user)
    
    db.close()
    
    return redirect('/profile')

# @app.route('/messaging', methods=['GET', 'POST'])    
#     db = SessionLocal()
#     users = db.query(User).filter(User.username != username).all()
#     messages = []
#     selected_user = None

#     if request.method == 'POST':
#         recipient = request.form['recipient']
#         content = request.form['content']
#         new_message = Message(sender=username, recipient=recipient, content=content)
#         db.add(new_message)
#         db.commit()
#         selected_user = recipient

#     if request.method == 'POST' or request.args.get('user'):
#         selected_user = selected_user or request.args.get('user')
#         if selected_user:
#             messages = db.query(Message).filter(
#                 ((Message.sender == username) & (Message.recipient == selected_user)) |
#                 ((Message.sender == selected_user) & (Message.recipient == username))
#             ).all()
    
#     db.close()
#     return render_template('messaging.html', username=username, users=users, messages=messages, selected_user=selected_user)

if __name__ == '__main__':
    Base.metadata.create_all(bind=engine)
    app.run(debug=True)

