import os
from pathlib import Path
from dotenv import load_dotenv
BASE=Path(__file__).resolve().parents[1]
load_dotenv(BASE.parent/'.env')
class Config:
    SECRET_KEY=os.getenv('SECRET_KEY','mailtrace-dev-secret-change-in-production-32chars')
    JWT_SECRET_KEY=os.getenv('JWT_SECRET_KEY','mailtrace-jwt-secret-change-in-production-32chars')
    SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL',f"sqlite:///{BASE/'mailtrace.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS=False
    CORS_ORIGINS=os.getenv('CORS_ORIGINS','http://localhost:5173')
    ENABLE_EXTERNAL_INTEL=os.getenv('ENABLE_EXTERNAL_INTEL','false').lower()=='true'
    IP_GEO_API_URL=os.getenv('IP_GEO_API_URL','https://ipapi.co/{ip}/json/')
    MAX_CONTENT_LENGTH=10*1024*1024
