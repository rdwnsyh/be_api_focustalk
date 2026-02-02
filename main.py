from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, EmailStr
from google.oauth2 import id_token
from google.auth.transport import requests
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
import os
import traceback

# ===========================
# SECURITY SETUP
# ===========================

def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt"""
    # Ensure password is encoded as bytes and truncate to 72 bytes if needed
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    
    # Generate salt and hash
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    # Ensure password is encoded as bytes and truncate to 72 bytes if needed
    password_bytes = plain_password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    
    # Hash must be in bytes
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

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
    
    # Leaderboard/Progress Fields
    total_solved = Column(Integer, default=0, nullable=False)
    current_streak = Column(Integer, default=0, nullable=False)
    last_active = Column(DateTime, default=datetime.utcnow, nullable=False)

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

class UserProgressUpdate(BaseModel):
    email: EmailStr
    solved_increment: int
    streak: int

class LeaderboardEntry(BaseModel):
    name: str
    picture: str = None
    total_solved: int
    current_streak: int

# ===========================
# FASTAPI APP
# ===========================

app = FastAPI(title="FocusTalk API", version="1.0.0")

# Add exception handlers for better error responses
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions"""
    print(f"❌ Unhandled exception: {str(exc)}")
    print(f"📋 Traceback: {traceback.format_exc()}")
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "detail": str(exc),
            "type": type(exc).__name__
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors"""
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": "Validation error",
            "detail": exc.errors()
        }
    )

# Google Client ID
GOOGLE_CLIENT_ID = "383786989370-tegl1qqrjaj72u313k8tok1peojo9fao.apps.googleusercontent.com"

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
    try:
        print(f"📝 Attempting to register user: {user_data.email}")
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Email already registered. Please use a different email or login."
            )
        
        # Validate password length (in bytes for bcrypt)
        password_bytes = user_data.password.encode('utf-8')
        if len(user_data.password) < 6:
            raise HTTPException(
                status_code=400,
                detail="Password must be at least 6 characters long"
            )
        
        if len(password_bytes) > 72:
            raise HTTPException(
                status_code=400,
                detail="Password is too long (max 72 bytes). Please use a shorter password."
            )
        
        print(f"🔐 Hashing password...")
        # Hash the password
        hashed_password = get_password_hash(user_data.password)
        
        print(f"👤 Creating new user in database...")
        # Create new user
        new_user = User(
            email=user_data.email,
            full_name=user_data.full_name,
            password_hash=hashed_password,
            google_id=None,
            picture=None,
            total_solved=0,
            current_streak=0,
            last_active=datetime.utcnow()
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        print(f"✅ User registered successfully: {new_user.email}")
        
        # Return user info
        return {
            "success": True,
            "token": f"focustalk_token_{new_user.id}",
            "email": new_user.email,
            "name": new_user.full_name,
            "picture": new_user.picture,
            "user_id": new_user.id,
            "message": "Registration successful!"
        }
    
    except HTTPException as he:
        # Re-raise HTTP exceptions
        raise he
    except Exception as e:
        print(f"❌ Registration error: {str(e)}")
        print(f"📋 Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Registration failed: {str(e)}"
        )

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
    
    # Update last_active
    user.last_active = datetime.utcnow()
    db.commit()
    
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
            # User exists, update Google ID if not set and update last_active
            if user.google_id is None:
                user.google_id = google_user_id
                user.picture = picture
            user.last_active = datetime.utcnow()
            db.commit()
            db.refresh(user)
        else:
            # Create new user
            user = User(
                email=email,
                full_name=name,
                password_hash=None,  # Google users don't have password
                google_id=google_user_id,
                picture=picture,
                total_solved=0,
                current_streak=0,
                last_active=datetime.utcnow()
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
            "auth_method": "google" if user.google_id else "email",
            "total_solved": user.total_solved,
            "current_streak": user.current_streak
        }
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ===========================
# PROGRESS & LEADERBOARD ENDPOINTS
# ===========================

@app.post("/user/sync_progress")
async def sync_progress(progress: UserProgressUpdate, db: Session = Depends(get_db)):
    """
    Sync user's learning progress from the app
    Updates total solved questions and streak
    """
    # Find user by email
    user = db.query(User).filter(User.email == progress.email).first()
    
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found. Please login first."
        )
    
    # Update user progress
    user.total_solved += progress.solved_increment
    user.current_streak = progress.streak
    user.last_active = datetime.utcnow()
    
    db.commit()
    db.refresh(user)
    
    return {
        "success": True,
        "message": "Progress synced successfully",
        "total_solved": user.total_solved,
        "current_streak": user.current_streak
    }

@app.get("/leaderboard")
async def get_leaderboard(db: Session = Depends(get_db)):
    """
    Get top 20 users ranked by total solved questions
    """
    # Query users ordered by total_solved descending
    top_users = db.query(User).order_by(User.total_solved.desc()).limit(20).all()
    
    # Format response
    leaderboard = []
    for rank, user in enumerate(top_users, start=1):
        leaderboard.append({
            "rank": rank,
            "name": user.full_name,
            "picture": user.picture,
            "total_solved": user.total_solved,
            "current_streak": user.current_streak
        })
    
    return {
        "success": True,
        "leaderboard": leaderboard
    }
