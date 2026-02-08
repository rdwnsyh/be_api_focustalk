from fastapi import FastAPI, HTTPException, Depends, Form, File, UploadFile
from fastapi.staticfiles import StaticFiles
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
import shutil
from pathlib import Path

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
    solved_count = Column(Integer, default=0, nullable=False)  # Track quiz progress
    streak = Column(Integer, default=0, nullable=False)  # Track daily streak

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

class SyncProgressRequest(BaseModel):
    email: EmailStr
    solved_increment: int
    streak: int

# ===========================
# FASTAPI APP
# ===========================

app = FastAPI(title="FocusTalk API", version="1.0.0")

# Create static directory if it doesn't exist
static_dir = Path("static")
static_dir.mkdir(exist_ok=True)
profile_images_dir = static_dir / "profile_images"
profile_images_dir.mkdir(exist_ok=True)

# Mount static files directory for profile images
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
    logger.info("✅ Static files mounted successfully")
except Exception as e:
    logger.warning(f"⚠️ Could not mount static files: {e}")

# Enable CORS for Flutter app
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Google Client ID (Web Application)
GOOGLE_CLIENT_ID = "383786989370-tegl1qqrjaj72u313k8tok1peojo9fao.apps.googleusercontent.com"

# ===========================
# HELPER FUNCTIONS
# ===========================

def get_full_image_url(picture_path: str, base_url: str = "http://192.168.1.10:8000") -> str:
    """
    Convert relative image path to full URL
    If picture_path is already a full URL (starts with http), return as is
    """
    if not picture_path:
        return None
    
    if picture_path.startswith('http://') or picture_path.startswith('https://'):
        return picture_path
    
    # Remove leading slash if present
    picture_path = picture_path.lstrip('/')
    return f"{base_url}/{picture_path}"

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
        "picture": get_full_image_url(new_user.picture),
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
        "picture": get_full_image_url(user.picture),
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
            "picture": get_full_image_url(user.picture),
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
            "picture": get_full_image_url(user.picture),
            "auth_method": "google" if user.google_id else "email"
        }
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.put("/users/me")
async def update_current_user(
    token: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(None),
    image: UploadFile = File(None),
    db: Session = Depends(get_db)
):
    """
    Update current user profile
    Supports form data for name, email, optional password, and optional image
    """
    try:
        # Extract user_id from token
        user_id = int(token.replace("focustalk_token_", ""))
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if email is being changed and if it's already taken
        if email != user.email:
            existing_user = db.query(User).filter(User.email == email).first()
            if existing_user:
                raise HTTPException(
                    status_code=400,
                    detail="Email already taken by another user"
                )
        
        # Update user fields
        user.full_name = name
        user.email = email
        
        # Update password if provided
        if password and len(password.strip()) > 0:
            if len(password) < 6:
                raise HTTPException(
                    status_code=400,
                    detail="Password must be at least 6 characters long"
                )
            user.password_hash = get_password_hash(password)
        
        # Handle profile image upload
        if image and image.filename:
            try:
                # Create static/profile_images directory if it doesn't exist
                upload_dir = Path("static/profile_images")
                upload_dir.mkdir(parents=True, exist_ok=True)
                
                # Generate unique filename with timestamp
                file_extension = Path(image.filename).suffix.lower()
                # Validate file extension
                allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
                if file_extension not in allowed_extensions:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
                    )
                
                new_filename = f"user_{user_id}_{int(time.time())}{file_extension}"
                file_path = upload_dir / new_filename
                
                # Save the uploaded file
                with open(file_path, "wb") as buffer:
                    shutil.copyfileobj(image.file, buffer)
                
                # Update user picture URL (accessible via /static/profile_images/filename)
                user.picture = f"/static/profile_images/{new_filename}"
                logger.info(f"Profile image saved: {user.picture}")
                
            except HTTPException:
                raise
            except Exception as img_error:
                logger.error(f"Error saving profile image: {img_error}")
                # Don't fail the entire request if image upload fails
                # Just log the error and continue with other updates
        
        db.commit()
        db.refresh(user)
        
        return {
            "success": True,
            "message": "Profile updated successfully",
            "name": user.full_name,
            "email": user.email,
            "picture": get_full_image_url(user.picture)
        }
        
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")

# ===========================
# USER PROGRESS TRACKING
# ===========================

@app.post("/user/sync_progress")
async def sync_progress(request: SyncProgressRequest, db: Session = Depends(get_db)):
    """
    Sync user quiz progress (solved count and streak)
    """
    try:
        # Find user by email
        user = db.query(User).filter(User.email == request.email).first()
        
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        # Update solved count
        user.solved_count += request.solved_increment
        
        # Update streak (frontend sends the new streak value)
        user.streak = request.streak
        
        db.commit()
        db.refresh(user)
        
        logger.info(f"✅ Progress synced for {request.email}: solved={user.solved_count}, streak={user.streak}")
        
        return {
            "success": True,
            "message": "Progress synced successfully",
            "solved_count": user.solved_count,
            "streak": user.streak
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error syncing progress: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to sync progress: {str(e)}")
