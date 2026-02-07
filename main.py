from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from google.oauth2 import id_token
from google.auth.transport import requests
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
import time
import logging

# ===========================
# LOGGING SETUP
# ===========================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===========================
# SECURITY SETUP
# ===========================

# Password hashing context - reduced rounds for development (4 = ~100ms instead of 12 = ~500ms)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=4)

def get_password_hash(password: str) -> str:
    """
    bcrypt only supports passwords up to 72 bytes
    """
    password_bytes = password.encode("utf-8")

    if len(password_bytes) > 72:
        raise HTTPException(
            status_code=400,
            detail="Password terlalu panjang (maksimal 72 byte)"
        )

    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)

# ===========================
# DATABASE SETUP
# ===========================

# SQLite database
SQLALCHEMY_DATABASE_URL = "sqlite:///./focustalk.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Model
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    password_hash = Column(String, nullable=True)  # Nullable for Google OAuth users
    google_id = Column(String, unique=True, nullable=True)  # For Google OAuth users
    picture = Column(String, nullable=True)

# Create tables
Base.metadata.create_all(bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ===========================
# PYDANTIC SCHEMAS
# ===========================

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class GoogleSignInRequest(BaseModel):
    id_token: str

class UserResponse(BaseModel):
    success: bool
    token: str
    email: str
    name: str
    picture: str = None
    user_id: int

# ===========================
# FASTAPI APP
# ===========================

app = FastAPI(title="FocusTalk API", version="1.0.0")

# Google Client ID
GOOGLE_CLIENT_ID = "970950673922-5mecnlsjs82007ji8tp87ba9153tl22i.apps.googleusercontent.com"

# ===========================
# ENDPOINTS
# ===========================

@app.get("/")
def read_root():
    return {
        "message": "FocusTalk API is running!",
        "version": "1.0.0",
        "endpoints": {
            "google_auth": "POST /auth/google",
            "register": "POST /auth/register",
            "login": "POST /auth/login"
        }
    }

# ===========================
# EMAIL/PASSWORD AUTHENTICATION
# ===========================

@app.post("/auth/register")
async def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user with email and password
    """
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered. Please use a different email or login."
        )
    
    # Validate password length
    if len(user_data.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters long"
        )
    
    if len(user_data.password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=400,
            detail="Password terlalu panjang (maksimal 72 byte)"
    )
    
    # Hash the password
    hashed_password = get_password_hash(user_data.password)
    
    # Create new user
    new_user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        password_hash=hashed_password,
        google_id=None,
        picture=None
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Return user info
    return {
        "success": True,
        "token": f"focustalk_token_{new_user.id}",  # In production, use proper JWT
        "email": new_user.email,
        "name": new_user.full_name,
        "picture": new_user.picture,
        "user_id": new_user.id,
        "message": "Registration successful!"
    }


@app.post("/auth/login")
async def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """
    Login with email and password
    """
    # Find user by email
    user = db.query(User).filter(User.email == credentials.email).first()
    
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Incorrect email or password"
        )
    
    # Check if user registered via Google (no password)
    if user.password_hash is None:
        raise HTTPException(
            status_code=400,
            detail="This account was created with Google. Please use Google Sign-In."
        )
    
    # Verify password
    if not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=400,
            detail="Incorrect email or password"
        )
    
    # Return user info
    return {
        "success": True,
        "token": f"focustalk_token_{user.id}",  # In production, use proper JWT
        "email": user.email,
        "name": user.full_name,
        "picture": user.picture,
        "user_id": user.id,
        "message": "Login successful!"
    }

# ===========================
# GOOGLE AUTHENTICATION
# ===========================

@app.post("/auth/google")
async def google_auth(request: GoogleSignInRequest, db: Session = Depends(get_db)):
    """
    Authenticate user with Google ID Token
    """
    try:
        # Verify the ID token with Google
        idinfo = id_token.verify_oauth2_token(
            request.id_token, 
            requests.Request(), 
            GOOGLE_CLIENT_ID
        )
        
        # Extract user information
        google_user_id = idinfo['sub']
        email = idinfo.get('email')
        name = idinfo.get('name')
        picture = idinfo.get('picture')
        
        # Check if user exists
        user = db.query(User).filter(User.email == email).first()
        
        if user:
            # User exists, update Google ID if not set
            if user.google_id is None:
                user.google_id = google_user_id
                user.picture = picture
                db.commit()
                db.refresh(user)
        else:
            # Create new user
            user = User(
                email=email,
                full_name=name,
                password_hash=None,  # Google users don't have password
                google_id=google_user_id,
                picture=picture
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        
        return {
            "success": True,
            "token": f"focustalk_token_{user.id}",  # In production, use proper JWT
            "email": user.email,
            "name": user.full_name,
            "picture": user.picture,
            "user_id": user.id
        }
        
    except ValueError as e:
        # Invalid token
        raise HTTPException(status_code=401, detail=f"Invalid ID token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication error: {str(e)}")

# ===========================
# EXAMPLE ENDPOINTS
# ===========================

@app.get("/soal")
def ambil_soal():
    """Example endpoint for quiz questions"""
    return {
        "id": 1,
        "pertanyaan": "What is the synonym of 'Delay'?",
        "jawaban": "Procrastinate"
    }

@app.get("/users/me")
async def get_current_user(token: str, db: Session = Depends(get_db)):
    """
    Get current user info by token
    Example: /users/me?token=focustalk_token_1
    """
    # Extract user_id from token (in production, use proper JWT parsing)
    try:
        user_id = int(token.replace("focustalk_token_", ""))
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "user_id": user.id,
            "email": user.email,
            "name": user.full_name,
            "picture": user.picture,
            "auth_method": "google" if user.google_id else "email"
        }
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token")
