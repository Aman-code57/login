from fastapi import FastAPI, Form, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse,JSONResponse
from jose import jwt
from fastapi.security import HTTPBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
import mysql.connector
import re
import secrets

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

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9@#$%^&*!]{6,12}$")
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

@app.get("/signup.html", response_class=HTMLResponse)
def get_signup_page():
    with open("signup.html", "r") as f:
        return f.read()

@app.get("/homepage.html", response_class=HTMLResponse)
def get_homepage():
    with open("homepage.html", "r") as f:
        return f.read()
    
@app.get("/signup.html/index.html", response_class=HTMLResponse)
def get_back_loginpage():
    with open("index.html","r") as f:
        return f.read()
    
@app.get("/signup.html/signup.html", response_class=HTMLResponse)
def get_backto_back_signuppage():
    with open("signup.html","r") as f :
        return f.read()
    
@app.get("/index.html", response_class=HTMLResponse)
def get_back_loginpage():
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

# Sign UP
@app.post("/signup")
async def register_admin(
    request: Request,
    fullname: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    email: str = Form(...),
    mobileno: str = Form(...)
):

    if not USERNAME_REGEX.match(username):
        return {"error": "Invalid username format."}

    if password != confirm_password:
        return {"error": "Passwords do not match"}

    if not PASSWORD_REGEX.match(password):
        return {"error": "password must contain 8 any characters"}

    hashed_pw = hash_password(password)


    db = get_db()
    cursor = db.cursor()

    # Check if username already exists
    cursor.execute("SELECT * FROM admins WHERE username = %s", (username,))
    existing_user = cursor.fetchone()
    if existing_user:
        cursor.close()
        db.close()
        return {"error": "Username already registered"}

    cursor.execute(
        "INSERT INTO admins (fullname, username, password, email, mobileno) VALUES (%s, %s, %s, %s, %s)",
        (fullname, username, hashed_pw, email, mobileno)
    )
    db.commit()
    cursor.close()
    db.close()

    token = create_access_token({"sub": username})
    return JSONResponse({"access_token": token, "token_type": "bearer"})

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

@app.post("/verify")
async def verify_user(method: str = Form(...), inputValue: str = Form(...)):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    if method == "email":
        if not EMAIL_REGEX.match(inputValue):
            cursor.close()
            db.close()
            return JSONResponse({"error": "Invalid email format"}, status_code=400)
        cursor.execute("SELECT * FROM admins WHERE email = %s", (inputValue,))
    elif method == "mobileno":
        if not MOBILE_REGEX.match(inputValue):
            cursor.close()
            db.close()
            return JSONResponse({"error": "Invalid mobile number format"}, status_code=400)
        cursor.execute("SELECT * FROM admins WHERE mobileno = %s", (inputValue,))
    else:
        cursor.close()
        db.close()
        return JSONResponse({"error": "Invalid method"}, status_code=400)

    user = cursor.fetchone()
    cursor.close()
    db.close()

    if not user:
        return JSONResponse({"error": "User not found"}, status_code=404)

    # Generate reset token
    reset_token = secrets.token_urlsafe(32)

    # Store token in DB
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE admins SET reset_token = %s WHERE id = %s", (reset_token, user["id"]))
    db.commit()
    cursor.close()
    db.close()

    # Redirect to forgot password page with token
    return RedirectResponse(url=f"/forgot_password.html?token={reset_token}", status_code=303)

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
        "INSERT INTO users (fullname, username, address, mobilenumber) VALUES (%s, %s, %s, %s)",
        (fullname, username, address, mobilenumber)
    )
    db.commit()
    cursor.close()
    db.close()

    return RedirectResponse(url="/homepage.html", status_code=303)

@app.post("/update")                          # Update the userlist
async def update_user(
    request: Request,
    id : str = Form(...),                     # This identifies the user to update
    fullname: str = Form(...),
    username: str = Form(...),  
    address: str = Form(...),
    mobilenumber: str = Form(...)
):
    db = get_db()
    cursor = db.cursor()

    #  Correct SQL with WHERE clause
    cursor.execute(
        "UPDATE users SET fullname = %s, username = %s, address = %s, mobilenumber = %s WHERE id = %s",
        (fullname, username, address, mobilenumber, id)
    )

    db.commit()
    cursor.close()
    db.close()

    #  Redirect to homepage
    return RedirectResponse(url="/homepage.html", status_code=303)


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

