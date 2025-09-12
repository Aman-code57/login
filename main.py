from fastapi import FastAPI, Form, Request, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse, RedirectResponse,JSONResponse
from jose import jwt
from fastapi.security import HTTPBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
import mysql.connector
import re
import secrets
import random, smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv


# Load environment variables from .env
load_dotenv()

app = FastAPI()
security = HTTPBearer()
USERNAME_REGEX = re.compile(r"^(?=[A-Za-z][A-Za-z0-9@#$%^&*!]{5,11}$)(?=(?:[^0-9]*[0-9]){2}[^0-9]*$)(?=(?:[^@#$%^&*!]*[@#$%^&*!]){1}[^@#$%^&*!]*$)[A-Za-z0-9@#$%^&*!]+$")  # simpler email regex
PASSWORD_REGEX = re.compile(r"^.{8,}$")



SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: dict = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # decoded JWT (can access username with payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
def get_current_user(authorization: str = Header(None)):
    """
    Verify JWT from Authorization header.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid auth scheme")
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # contains username in payload["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
MOBILE_REGEX = re.compile(r"^[0-9]{10}$")  # 10-digit mobile number


def get_db():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="Rockstar@5057",
        database="login"
    )

@app.get("/", response_class=HTMLResponse)
def get_login_page():
    with open("index.html", "r") as f:
        return f.read()

@app.get("/signup", response_class=HTMLResponse)
def get_signup_page():
    with open("signup.html", "r") as f:
        return f.read()

@app.get("/homepage", response_class=HTMLResponse)
def get_homepage():
    with open("homepage.html", "r") as f:
        return f.read()

    
@app.get("/index.html", response_class=HTMLResponse)
def get_back_loginpage(user: dict = Depends(get_current_user)):
    with open("index.html","r") as f:
        return f.read()

@app.get("/create_user.html", response_class=HTMLResponse)
def get_homepage():
    with open("create_user.html", "r") as f:
        return f.read()
    
@app.get("/update",response_class=HTMLResponse)
def get_updatepage():
    with open("update.html","r") as f:
        return f.read()

@app.get("/verification.html",response_class=HTMLResponse)
def get_verify():
    with open("verification.html","r") as f:
        return f.read()
    
@app.get("/verification.html/index.html",response_class=HTMLResponse)
def get_backlogin():
    with open("index.html","r") as f:
        return f.read()
    
@app.get("/verification.html/forgot_password.html",response_class=HTMLResponse)
def get_backlogin():
    with open("forgot_password.html","r") as f:
        return f.read()

@app.get("/forgot_password.html", response_class=HTMLResponse)
def get_forgot_password():
    with open("forgot_password.html", "r") as f:
        return f.read()
    
@app.get("/admin_verification.html", response_class=HTMLResponse)
def get_admin_verify():
    with open("admin_verification.html", "r") as f:
        return f.read()
    
@app.get("/otp.html",response_class=HTMLResponse)
def get_otp_verify():
    with open("otp.html", "r") as f:
        return f.read()
    



# update
@app.get("/api/user")
async def get_user_by_id(id: str):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE id = %s", (id,))
    user = cursor.fetchone()

    cursor.close()
    db.close()

    if user:
        return JSONResponse(content=user)
    return JSONResponse(content={"error": "User not found"}, status_code=404)  



# Login
@app.post("/")
async def login_admin(username: str = Form(...), password: str = Form(...)):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admins WHERE username = %s", (username,))
    user = cursor.fetchone()

    cursor.close()
    db.close()
    
    if user and verify_password(password, user["password"]):
        token = create_access_token({"sub": username})
        return JSONResponse({
            "access_token": token,
            "token_type": "bearer",
            "message": "Login successful"
        })
    else:
        return JSONResponse({"error": "Invalid username or password"}, status_code=401)
    
# Email Sender 
EMAIL_USER = os.getenv("EMAIL_USER", "amanraturi5757@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "epif azzt hgjg zvcy")

def send_email(subject, body, sender, recipients, password):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp_server:
        smtp_server.login(sender, password)
        smtp_server.sendmail(sender, recipients, msg.as_string())
    print("OTP sent to email!")


# FOR VERIFICATION RESET PASSWORD
@app.post("/verify")
async def verify_user(method: str = Form(...), inputValue: str = Form(...)):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    if method == "email":
        cursor.execute("SELECT * FROM admins WHERE email = %s", (inputValue,))
    elif method == "mobileno":
        cursor.execute("SELECT * FROM admins WHERE mobileno = %s", (inputValue,))
    else:
        cursor.close()
        db.close()
        return JSONResponse({"error": "Invalid method"}, status_code=400)

    user = cursor.fetchone()
    if not user:
        cursor.close()
        db.close()
        return JSONResponse({"error": "User not found"}, status_code=404)

    # Generate OTP
    otp = str(random.randint(100000, 999999))
    expiry = datetime.utcnow() + timedelta(minutes=5)

    cursor.execute("UPDATE admins SET otp_code=%s, otp_expiry=%s WHERE id=%s",
                   (otp, expiry, user["id"]))
    db.commit()
    cursor.close()
    db.close()

    # Send email
    subject = "Your Verification OTP"
    body = f"Your OTP is {otp}. It is valid for 5 minutes."
    recipients = [user["email"]]
    try:
        send_email(subject, body, EMAIL_USER, recipients, EMAIL_PASSWORD)
    except Exception as e:
        return JSONResponse({"error": f"Failed to send OTP email: {str(e)}"}, status_code=500)

    return RedirectResponse(url="/otp.html", status_code=303)

# VERIFY FOR RESET PASSWORD
@app.post("/verify_reset_otp")
async def verify_reset_otp(otp: str = Form(...)):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admins WHERE otp_code=%s", (otp,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        db.close()
        return JSONResponse({"error": "Invalid OTP"}, status_code=400)

    if user["otp_expiry"] < datetime.utcnow():
        cursor.close()
        db.close()
        return JSONResponse({"error": "OTP expired"}, status_code=400)

    reset_token = secrets.token_urlsafe(32)
    cursor.execute("UPDATE admins SET reset_token=%s, otp_code=NULL, otp_expiry=NULL WHERE id=%s",
                   (reset_token, user["id"]))
    db.commit()
    cursor.close()
    db.close()

    redirect_url = f"/forgot_password.html?token={reset_token}"
    return RedirectResponse(url=redirect_url, status_code=303)


# FOR RESET PASSWORD
@app.post("/reset_password")
async def reset_password(token: str = Form(...), password: str = Form(...), confirmPassword: str = Form(...)):
    if password != confirmPassword:
        return JSONResponse({"error": "Passwords do not match"}, status_code=400)

    if not PASSWORD_REGEX.match(password):
        return JSONResponse({"error": "Password must contain at least 8 characters"}, status_code=400)

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admins WHERE reset_token = %s", (token,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        db.close()
        return JSONResponse({"error": "Invalid or expired token"}, status_code=400)

    hashed_pw = hash_password(password)
    cursor.execute("UPDATE admins SET password = %s, reset_token = NULL WHERE id = %s", (hashed_pw, user["id"]))
    db.commit()
    cursor.close()
    db.close()

    return RedirectResponse(url="/", status_code=303)

# Read the table
@app.get("/api/users")
async def get_userlist(user: dict = Depends(verify_token)):
    db = get_db()
    cursor = db.cursor(dictionary=True)  # Get rows as dicts
    
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    cursor.close()
    db.close()
    
    return JSONResponse(content=users)

@app.post("/create_user")                  # Create new user in userlist
async def register_user(
    request: Request,
    
    fullname: str = Form(...),
    username: str = Form(...),
    address: str = Form(...),
    mobilenumber: str = Form(...)
):
   
    db = get_db()
    cursor = db.cursor()
    
    #check if already exists
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    existing_user = cursor.fetchone()
    if existing_user:
        cursor.close()
        db.close()
        return {"error": "user already registered"}

    cursor.execute(
        "INSERT INTO users (fullname, username, address, mobilenumber) VALUES ( %s, %s, %s, %s)",
        (fullname, username, address, mobilenumber)
    )
    db.commit()
    cursor.close()
    db.close()

    return RedirectResponse(url="/homepage", status_code=303)

@app.post("/update")                          # Update the userlist
async def update_user(
    request: Request, # This identifies the user to update
    id: str = Form(...),
    fullname: str = Form(...),
    username: str = Form(...),
    address: str = Form(...),
    mobilenumber: str = Form(...)
):
    db = get_db()
    cursor = db.cursor()

    #  Correct SQL with WHERE clause using serialno as primary key
    cursor.execute(
        "UPDATE users SET fullname = %s, username = %s, address = %s, mobilenumber = %s WHERE id = %s",
        (fullname, username, address, mobilenumber, id)
    )

    db.commit()
    cursor.close()
    db.close()

    #  Redirect to homepage
    return RedirectResponse(url="/homepage", status_code=303)


# delete
@app.delete("/api/delete")
async def delete_user(username: str):
    db = get_db()
    cursor = db.cursor()

    # Ensure you're using a safe query (parameterized)
    cursor.execute("DELETE FROM users WHERE username = %s", (username,))
    db.commit()

    cursor.close()
    db.close()

    return JSONResponse(content={"message": "User deleted successfully"})


# register new admin
@app.post("/signup")
async def signup(
    fullname: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    email: str = Form(...),
    mobileno: str = Form(...)
):
    if not EMAIL_REGEX.match(email):
        return JSONResponse({"error": "Invalid email format"}, status_code=400)

    if password != confirm_password:
        return JSONResponse({"error": "Passwords do not match"}, status_code=400)

    if not PASSWORD_REGEX.match(password):
        return JSONResponse({"error": "Password must be at least 8 characters"}, status_code=400)

    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Check if email/username already exists
    cursor.execute("SELECT * FROM admins WHERE email=%s OR username=%s", (email, username))
    if cursor.fetchone():
        cursor.close()
        db.close()
        return JSONResponse({"error": "Email or username already registered"}, status_code=400)

    # Generate OTP
    otp = str(random.randint(100000, 999999))
    hashed_pw = hash_password(password)

    # Store temporarily in pending_users
    cursor.execute(
        """INSERT INTO pending_users (fullname, username, password, email, mobileno, otp, otp_created_at)
           VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
        (fullname, username, hashed_pw, email, mobileno, otp)
    )
    db.commit()
    cursor.close()
    db.close()

    # Send OTP via email
    subject = "Your Verification OTP"
    body = f"Hello {fullname},\n\nYour OTP for signup is: {otp}\n\nIt will expire in 5 minutes."

    try:
        sender_email = "amanraturi5757@gmail.com"
        receiver_email = email
        email_password = "epif azzt hgjg zvcy"  # App password

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = receiver_email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, email_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            print("otp sent")

    except Exception as e:
        return JSONResponse({"error": f"Failed to send OTP: {str(e)}"}, status_code=500)

    return JSONResponse({"message": "OTP sent to your email. Please verify."})

# VERIFY OTP FOR SIGNUP 
@app.post("/verify_otp")
async def verify_otp(email: str = Form(...), otp: str = Form(...)):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Check OTP validity (expire after 5 minutes)
    cursor.execute(
        """SELECT * FROM pending_users 
           WHERE email=%s AND otp=%s AND TIMESTAMPDIFF(MINUTE, otp_created_at, NOW()) <= 5""",
        (email, otp)
    )
    user = cursor.fetchone()

    if not user:
        cursor.close()
        db.close()
        return JSONResponse({"error": "Invalid or expired OTP"}, status_code=400)

    # Insert into admins table
    cursor.execute(
        "INSERT INTO admins (fullname, username, password, email, mobileno) VALUES (%s, %s, %s, %s, %s)",
        (user["fullname"], user["username"], user["password"], user["email"], user["mobileno"])
    )
    db.commit()

    # Remove from pending_users
    cursor.execute("DELETE FROM pending_users WHERE id=%s", (user["id"],))
    db.commit()

    cursor.close()
    db.close()

    return RedirectResponse(url="/", status_code=303)






















