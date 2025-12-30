# main.py - FastAPI сервер лицензий для Render
import os
import json
import hashlib
import secrets
import uuid
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from enum import Enum

# FastAPI и зависимости
from fastapi import FastAPI, HTTPException, Depends, status, Request, Response, Form, File, UploadFile
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.websockets import WebSocket
import uvicorn

# База данных и кэш
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.pool import NullPool
import asyncpg
from redis import asyncio as aioredis

# Безопасность
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, Field, validator
import cryptography
from cryptography.fernet import Fernet

# Дополнительные утилиты
import aiohttp
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
import time
import ipaddress

# Загрузка переменных окружения
load_dotenv()

# ==================== КОНФИГУРАЦИЯ ====================
class Settings(BaseModel):
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    REDIS_URL: Optional[str] = Field(None, env="REDIS_URL")
    JWT_SECRET: str = Field(..., env="JWT_SECRET")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 дней
    ADMIN_API_KEY: str = Field(..., env="ADMIN_API_KEY")
    TELEGRAM_BOT_TOKEN: Optional[str] = Field(None, env="TELEGRAM_BOT_TOKEN")
    API_BASE_URL: str = Field("https://mangabuff-license-api.onrender.com", env="API_BASE_URL")
    NODE_ENV: str = Field("production", env="NODE_ENV")
    RATE_LIMIT_PER_MINUTE: int = 60
    CACHE_TTL: int = 300
    
    @validator('DATABASE_URL')
    def validate_database_url(cls, v):
        if not v.startswith('postgresql://'):
            raise ValueError('DATABASE_URL должен начинаться с postgresql://')
        return v

# Инициализация настроек
settings = Settings()

# ==================== ЛОГИРОВАНИЕ ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('license_server.log', maxBytes=10*1024*1024, backupCount=5),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# ==================== FASTAPI ПРИЛОЖЕНИЕ ====================
app = FastAPI(
    title="MangaBuff License API",
    description="Система управления лицензиями для MangaBuff Automation",
    version="2.0.0",
    docs_url="/api/docs" if settings.NODE_ENV != "production" else None,
    redoc_url="/api/redoc" if settings.NODE_ENV != "production" else None,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Подключение статических файлов
app.mount("/static", StaticFiles(directory="static"), name="static")

# Шаблоны
templates = Jinja2Templates(directory="templates")

# ==================== БАЗА ДАННЫХ ====================
# Синхронное подключение для SQLAlchemy ORM
engine = create_engine(
    settings.DATABASE_URL,
    poolclass=NullPool,
    echo=settings.NODE_ENV == "development"
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==================== МОДЕЛИ БАЗЫ ДАННЫХ ====================
class License(Base):
    __tablename__ = "licenses"
    
    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String(64), unique=True, index=True, nullable=False)
    hardware_id = Column(String(64), index=True, nullable=True)
    user_email = Column(String(120), index=True, nullable=True)
    user_name = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    last_check = Column(DateTime, nullable=True)
    check_count = Column(Integer, default=0)
    notes = Column(Text, nullable=True)
    metadata = Column(Text, default="{}")  # JSON поле для дополнительных данных
    
    # Связи
    logs = relationship("ActivityLog", back_populates="license", cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            "id": self.id,
            "license_key": self.license_key,
            "hardware_id": self.hardware_id,
            "user_email": self.user_email,
            "user_name": self.user_name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "check_count": self.check_count,
            "notes": self.notes,
            "days_left": (self.expires_at - datetime.utcnow()).days if self.expires_at and self.expires_at > datetime.utcnow() else 0,
            "is_expired": self.expires_at < datetime.utcnow() if self.expires_at else False
        }

class ActivityLog(Base):
    __tablename__ = "activity_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(Integer, ForeignKey("licenses.id"), nullable=True)
    action = Column(String(50), nullable=False)
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    details = Column(Text, nullable=True)
    
    # Связи
    license = relationship("License", back_populates="logs")

class AdminUser(Base):
    __tablename__ = "admin_users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, index=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    email = Column(String(120), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    def verify_password(self, password: str, pwd_context: CryptContext) -> bool:
        return pwd_context.verify(password, self.password_hash)

class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    reason = Column(String(100), nullable=True)
    blocked_at = Column(DateTime, default=datetime.utcnow)
    blocked_until = Column(DateTime, nullable=True)
    created_by = Column(String(80), nullable=True)
    
    def is_active(self):
        if not self.blocked_until:
            return True
        return datetime.utcnow() < self.blocked_until

class APIToken(Base):
    __tablename__ = "api_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    admin_id = Column(Integer, ForeignKey("admin_users.id"), nullable=True)
    permissions = Column(Text, default="[]")  # JSON список разрешений
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

# Создание таблиц
Base.metadata.create_all(bind=engine)

# ==================== PYDANTIC МОДЕЛИ ====================
class LicenseCreate(BaseModel):
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    days_valid: int = Field(30, ge=1, le=3650)
    notes: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class LicenseUpdate(BaseModel):
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    is_active: Optional[bool] = None
    notes: Optional[str] = None
    expires_at: Optional[datetime] = None
    hardware_id: Optional[str] = None

class ValidateRequest(BaseModel):
    license_key: str
    hardware_id: str

class ActivateRequest(BaseModel):
    license_key: str
    hardware_id: str
    user_name: Optional[str] = None
    user_email: Optional[str] = None

class AdminLogin(BaseModel):
    username: str
    password: str

class TokenData(BaseModel):
    admin_id: int
    username: str

# ==================== ЗАВИСИМОСТИ ====================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Зависимость для получения сессии БД
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Зависимость для получения Redis
async def get_redis():
    if not settings.REDIS_URL:
        return None
    
    redis = await aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True
    )
    try:
        yield redis
    finally:
        await redis.close()

# ==================== УТИЛИТЫ ====================
def generate_license_key() -> str:
    """Генерация лицензионного ключа в формате: XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX"""
    parts = [
        secrets.token_hex(4).upper(),
        secrets.token_hex(4).upper(),
        secrets.token_hex(4).upper(),
        secrets.token_hex(4).upper(),
        secrets.token_hex(6).upper()
    ]
    return '-'.join(parts)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return TokenData(**payload)
    except JWTError:
        return None

def log_activity(db: Session, license_id: Optional[int], action: str, 
                 ip_address: str, user_agent: str = None, details: str = None):
    """Логирование активности"""
    try:
        log = ActivityLog(
            license_id=license_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details
        )
        db.add(log)
        db.commit()
        
        logger.info(f"Activity: {action} - IP: {ip_address} - License: {license_id}")
        return log
    except Exception as e:
        logger.error(f"Failed to log activity: {e}")
        db.rollback()
        return None

# ==================== МИДЛВЭРЫ И ФИЛЬТРЫ ====================
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Простой rate limiting middleware"""
    client_ip = request.client.host
    
    # Пропускаем health checks
    if request.url.path in ["/", "/health", "/api/health"]:
        return await call_next(request)
    
    # Проверяем блокировку IP
    db = SessionLocal()
    try:
        blocked = db.query(BlockedIP).filter(
            BlockedIP.ip_address == client_ip,
            BlockedIP.blocked_until > datetime.utcnow()
        ).first()
        
        if blocked:
            logger.warning(f"Blocked IP tried to access: {client_ip}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Доступ запрещен"}
            )
    finally:
        db.close()
    
    # Rate limiting (упрощенный вариант)
    # В production используйте Redis для распределенного rate limiting
    redis = await aioredis.from_url(settings.REDIS_URL) if settings.REDIS_URL else None
    if redis:
        key = f"rate_limit:{client_ip}:{int(time.time() // 60)}"
        current = await redis.incr(key)
        await redis.expire(key, 60)
        
        if current > settings.RATE_LIMIT_PER_MINUTE:
            await redis.close()
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": "Слишком много запросов"}
            )
        await redis.close()
    
    response = await call_next(request)
    return response

# ==================== ЗАЩИЩЕННЫЕ ЗАВИСИМОСТИ ====================
async def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Получение текущего администратора по JWT токену"""
    token = credentials.credentials
    token_data = verify_token(token)
    
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Недействительный токен",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    admin = db.query(AdminUser).filter(AdminUser.id == token_data.admin_id).first()
    if not admin or not admin.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пользователь не найден или неактивен"
        )
    
    return admin

def require_admin_api_key(request: Request):
    """Проверка API ключа администратора"""
    api_key = request.headers.get("X-API-Key")
    if not api_key or api_key != settings.ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный API ключ"
        )

# ==================== API ЭНДПОИНТЫ ====================

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Корневая страница с информацией о API"""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "api_version": "2.0.0",
        "endpoints": [
            {"path": "/api/activate", "method": "POST", "description": "Активация лицензии"},
            {"path": "/api/validate", "method": "POST", "description": "Валидация лицензии"},
            {"path": "/api/licenses", "method": "GET", "description": "Список лицензий (требует аутентификации)"},
            {"path": "/api/health", "method": "GET", "description": "Проверка здоровья сервера"},
            {"path": "/api/docs", "method": "GET", "description": "Документация API"}
        ]
    })

@app.get("/health")
@app.get("/api/health")
async def health_check(db: Session = Depends(get_db)):
    """Проверка здоровья сервера и подключений"""
    try:
        # Проверка базы данных
        db.execute("SELECT 1")
        
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "services": {
                "database": "connected",
                "api": "running"
            },
            "version": "2.0.0",
            "environment": settings.NODE_ENV
        }
        
        # Проверка Redis если доступен
        if settings.REDIS_URL:
            try:
                redis = await aioredis.from_url(settings.REDIS_URL)
                await redis.ping()
                health_status["services"]["redis"] = "connected"
                await redis.close()
            except:
                health_status["services"]["redis"] = "disconnected"
        
        return health_status
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )

@app.post("/api/activate")
async def activate_license(
    request_data: ActivateRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Активация лицензии"""
    start_time = time.time()
    
    # Логирование запроса
    logger.info(f"Activation request: {request_data.license_key[:8]}... from {request.client.host}")
    
    # Проверка блокировки IP
    blocked = db.query(BlockedIP).filter(
        BlockedIP.ip_address == request.client.host,
        BlockedIP.blocked_until > datetime.utcnow()
    ).first()
    
    if blocked:
        log_activity(db, None, "ACTIVATE_BLOCKED", request.client.host, 
                    request.headers.get("user-agent"), f"Blocked IP: {request.client.host}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    # Поиск лицензии
    license_record = db.query(License).filter(
        License.license_key == request_data.license_key
    ).first()
    
    if not license_record:
        log_activity(db, None, "ACTIVATE_FAIL", request.client.host,
                    request.headers.get("user-agent"), f"License not found: {request_data.license_key[:8]}...")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Лицензия не найдена"
        )
    
    # Проверка активности лицензии
    if not license_record.is_active:
        log_activity(db, license_record.id, "ACTIVATE_FAIL", request.client.host,
                    request.headers.get("user-agent"), "License is inactive")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Лицензия неактивна"
        )
    
    # Проверка срока действия
    if license_record.expires_at and license_record.expires_at < datetime.utcnow():
        license_record.is_active = False
        db.commit()
        
        log_activity(db, license_record.id, "ACTIVATE_FAIL", request.client.host,
                    request.headers.get("user-agent"), "License expired")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Срок действия лицензии истек"
        )
    
    # Проверка привязки к hardware_id
    if license_record.hardware_id:
        if license_record.hardware_id != request_data.hardware_id:
            log_activity(db, license_record.id, "ACTIVATE_FAIL", request.client.host,
                        request.headers.get("user-agent"), 
                        f"Hardware ID mismatch. Expected: {license_record.hardware_id}, Got: {request_data.hardware_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Лицензия уже активирована на другом устройстве"
            )
        else:
            # Лицензия уже активирована на этом устройстве
            days_left = (license_record.expires_at - datetime.utcnow()).days if license_record.expires_at else None
            
            log_activity(db, license_record.id, "ACTIVATE_ALREADY", request.client.host,
                        request.headers.get("user-agent"), f"Already activated, days left: {days_left}")
            
            response_time = (time.time() - start_time) * 1000
            
            return {
                "success": True,
                "already_activated": True,
                "message": "Лицензия уже активирована на этом устройстве",
                "license": license_record.to_dict(),
                "days_left": days_left,
                "response_time_ms": response_time
            }
    
    # Активация лицензии
    license_record.hardware_id = request_data.hardware_id
    license_record.last_check = datetime.utcnow()
    license_record.check_count += 1
    
    if request_data.user_name and not license_record.user_name:
        license_record.user_name = request_data.user_name
    
    if request_data.user_email and not license_record.user_email:
        license_record.user_email = request_data.user_email
    
    db.commit()
    
    days_left = (license_record.expires_at - datetime.utcnow()).days if license_record.expires_at else None
    
    log_activity(db, license_record.id, "ACTIVATE_SUCCESS", request.client.host,
                request.headers.get("user-agent"), f"Activated on hardware: {request_data.hardware_id}")
    
    response_time = (time.time() - start_time) * 1000
    
    return {
        "success": True,
        "message": "Лицензия успешно активирована",
        "license": license_record.to_dict(),
        "days_left": days_left,
        "response_time_ms": response_time
    }

@app.post("/api/validate")
async def validate_license(
    request_data: ValidateRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Валидация лицензии"""
    start_time = time.time()
    
    logger.info(f"Validation request: {request_data.license_key[:8]}... from {request.client.host}")
    
    # Проверка блокировки IP
    blocked = db.query(BlockedIP).filter(
        BlockedIP.ip_address == request.client.host,
        BlockedIP.blocked_until > datetime.utcnow()
    ).first()
    
    if blocked:
        log_activity(db, None, "VALIDATE_BLOCKED", request.client.host,
                    request.headers.get("user-agent"), f"Blocked IP: {request.client.host}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ запрещен"
        )
    
    # Поиск лицензии
    license_record = db.query(License).filter(
        License.license_key == request_data.license_key
    ).first()
    
    if not license_record:
        log_activity(db, None, "VALIDATE_FAIL", request.client.host,
                    request.headers.get("user-agent"), f"License not found: {request_data.license_key[:8]}...")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Лицензия не найдена"
        )
    
    # Проверка активности лицензии
    if not license_record.is_active:
        log_activity(db, license_record.id, "VALIDATE_FAIL", request.client.host,
                    request.headers.get("user-agent"), "License is inactive")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Лицензия неактивна"
        )
    
    # Проверка срока действия
    if license_record.expires_at and license_record.expires_at < datetime.utcnow():
        license_record.is_active = False
        db.commit()
        
        log_activity(db, license_record.id, "VALIDATE_FAIL", request.client.host,
                    request.headers.get("user-agent"), "License expired")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Срок действия лицензии истек"
        )
    
    # Проверка привязки к hardware_id
    if license_record.hardware_id and license_record.hardware_id != request_data.hardware_id:
        log_activity(db, license_record.id, "VALIDATE_FAIL", request.client.host,
                    request.headers.get("user-agent"),
                    f"Hardware ID mismatch. Expected: {license_record.hardware_id}, Got: {request_data.hardware_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Лицензия привязана к другому устройству"
        )
    
    # Обновление времени последней проверки
    license_record.last_check = datetime.utcnow()
    license_record.check_count += 1
    db.commit()
    
    days_left = (license_record.expires_at - datetime.utcnow()).days if license_record.expires_at else None
    
    log_activity(db, license_record.id, "VALIDATE_SUCCESS", request.client.host,
                request.headers.get("user-agent"), f"Days left: {days_left}")
    
    response_time = (time.time() - start_time) * 1000
    
    return {
        "valid": True,
        "message": "Лицензия активна",
        "license": license_record.to_dict(),
        "days_left": days_left,
        "response_time_ms": response_time
    }

@app.get("/api/licenses")
async def list_licenses(
    request: Request,
    db: Session = Depends(get_db),
    current_admin: AdminUser = Depends(get_current_admin),
    page: int = 1,
    per_page: int = 20,
    search: Optional[str] = None,
    active_only: bool = False
):
    """Получение списка лицензий (только для администраторов)"""
    query = db.query(License)
    
    if active_only:
        query = query.filter(License.is_active == True)
    
    if search:
        query = query.filter(
            (License.license_key.contains(search)) |
            (License.user_email.contains(search)) |
            (License.user_name.contains(search)) |
            (License.hardware_id.contains(search))
        )
    
    total = query.count()
    licenses = query.order_by(License.id.desc()).offset((page - 1) * per_page).limit(per_page).all()
    
    log_activity(db, None, "LICENSES_LIST", request.client.host,
                request.headers.get("user-agent"), f"Admin: {current_admin.username}")
    
    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": (total + per_page - 1) // per_page,
        "licenses": [license.to_dict() for license in licenses]
    }

@app.post("/api/licenses")
async def create_license(
    license_data: LicenseCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Создание новой лицензии"""
    # Генерация уникального ключа
    license_key = generate_license_key()
    
    # Проверка на уникальность (маловероятно, но на всякий случай)
    while db.query(License).filter(License.license_key == license_key).first():
        license_key = generate_license_key()
    
    # Расчет даты истечения
    expires_at = datetime.utcnow() + timedelta(days=license_data.days_valid)
    
    # Создание лицензии
    license_record = License(
        license_key=license_key,
        user_email=license_data.user_email,
        user_name=license_data.user_name,
        expires_at=expires_at,
        notes=license_data.notes,
        metadata=json.dumps(license_data.metadata) if license_data.metadata else "{}"
    )
    
    db.add(license_record)
    db.commit()
    db.refresh(license_record)
    
    log_activity(db, license_record.id, "LICENSE_CREATE", request.client.host,
                request.headers.get("user-agent"), 
                f"Admin: {current_admin.username}, Days: {license_data.days_valid}")
    
    return {
        "success": True,
        "message": "Лицензия создана",
        "license": license_record.to_dict(),
        "license_key": license_key
    }

@app.get("/api/licenses/{license_id}")
async def get_license(
    license_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Получение информации о конкретной лицензии"""
    license_record = db.query(License).filter(License.id == license_id).first()
    
    if not license_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Лицензия не найдена"
        )
    
    # Получение логов для этой лицензии
    logs = db.query(ActivityLog).filter(
        ActivityLog.license_id == license_id
    ).order_by(ActivityLog.timestamp.desc()).limit(50).all()
    
    log_activity(db, license_id, "LICENSE_VIEW", request.client.host,
                request.headers.get("user-agent"), f"Admin: {current_admin.username}")
    
    return {
        "license": license_record.to_dict(),
        "logs": [
            {
                "id": log.id,
                "action": log.action,
                "ip_address": log.ip_address,
                "timestamp": log.timestamp.isoformat(),
                "details": log.details
            }
            for log in logs
        ]
    }

@app.put("/api/licenses/{license_id}")
async def update_license(
    license_id: int,
    license_data: LicenseUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Обновление лицензии"""
    license_record = db.query(License).filter(License.id == license_id).first()
    
    if not license_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Лицензия не найдена"
        )
    
    # Обновление полей
    update_fields = license_data.dict(exclude_unset=True)
    for field, value in update_fields.items():
        setattr(license_record, field, value)
    
    db.commit()
    db.refresh(license_record)
    
    log_activity(db, license_id, "LICENSE_UPDATE", request.client.host,
                request.headers.get("user-agent"), 
                f"Admin: {current_admin.username}, Fields: {list(update_fields.keys())}")
    
    return {
        "success": True,
        "message": "Лицензия обновлена",
        "license": license_record.to_dict()
    }

@app.delete("/api/licenses/{license_id}")
async def delete_license(
    license_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Удаление лицензии"""
    license_record = db.query(License).filter(License.id == license_id).first()
    
    if not license_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Лицензия не найдена"
        )
    
    # Удаление связанных логов
    db.query(ActivityLog).filter(ActivityLog.license_id == license_id).delete()
    
    # Удаление лицензии
    db.delete(license_record)
    db.commit()
    
    log_activity(db, None, "LICENSE_DELETE", request.client.host,
                request.headers.get("user-agent"), 
                f"Admin: {current_admin.username}, License: {license_record.license_key}")
    
    return {
        "success": True,
        "message": "Лицензия удалена"
    }

@app.post("/api/admin/login")
async def admin_login(
    login_data: AdminLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    """Аутентификация администратора"""
    admin = db.query(AdminUser).filter(
        AdminUser.username == login_data.username,
        AdminUser.is_active == True
    ).first()
    
    if not admin or not verify_password(login_data.password, admin.password_hash):
        log_activity(db, None, "ADMIN_LOGIN_FAIL", request.client.host,
                    request.headers.get("user-agent"), f"Username: {login_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный логин или пароль"
        )
    
    # Обновление времени последнего входа
    admin.last_login = datetime.utcnow()
    db.commit()
    
    # Создание JWT токена
    access_token = create_access_token(
        data={"sub": admin.username, "admin_id": admin.id, "username": admin.username}
    )
    
    log_activity(db, None, "ADMIN_LOGIN_SUCCESS", request.client.host,
                request.headers.get("user-agent"), f"Username: {login_data.username}")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "admin": {
            "id": admin.id,
            "username": admin.username,
            "email": admin.email
        }
    }

@app.get("/api/admin/stats")
async def get_admin_stats(
    request: Request,
    db: Session = Depends(get_db),
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Получение статистики для администратора"""
    total_licenses = db.query(License).count()
    active_licenses = db.query(License).filter(License.is_active == True).count()
    expired_licenses = db.query(License).filter(
        License.expires_at < datetime.utcnow()
    ).count()
    
    recent_activity = db.query(ActivityLog).order_by(
        ActivityLog.timestamp.desc()
    ).limit(10).all()
    
    # Статистика по дням (последние 7 дней)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    daily_stats = db.query(
        func.date(ActivityLog.timestamp).label('date'),
        func.count(ActivityLog.id).label('count')
    ).filter(
        ActivityLog.timestamp >= seven_days_ago,
        ActivityLog.action.in_(['ACTIVATE_SUCCESS', 'VALIDATE_SUCCESS'])
    ).group_by(func.date(ActivityLog.timestamp)).all()
    
    return {
        "total_licenses": total_licenses,
        "active_licenses": active_licenses,
        "expired_licenses": expired_licenses,
        "recent_activity": [
            {
                "id": activity.id,
                "action": activity.action,
                "ip_address": activity.ip_address,
                "timestamp": activity.timestamp.isoformat(),
                "license_id": activity.license_id,
                "details": activity.details
            }
            for activity in recent_activity
        ],
        "daily_stats": [
            {"date": stat.date.isoformat() if stat.date else None, "count": stat.count}
            for stat in daily_stats
        ]
    }

@app.post("/api/admin/block-ip")
async def block_ip(
    ip_address: str = Form(...),
    reason: str = Form("Многократные неудачные попытки"),
    hours: int = Form(24),
    request: Request = None,
    db: Session = Depends(get_db),
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Блокировка IP адреса"""
    try:
        # Валидация IP адреса
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неверный формат IP адреса"
        )
    
    # Проверка существующей блокировки
    existing = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
    
    if existing:
        # Обновление существующей блокировки
        existing.reason = reason
        existing.blocked_until = datetime.utcnow() + timedelta(hours=hours)
        existing.created_by = current_admin.username
    else:
        # Создание новой блокировки
        blocked = BlockedIP(
            ip_address=ip_address,
            reason=reason,
            blocked_until=datetime.utcnow() + timedelta(hours=hours),
            created_by=current_admin.username
        )
        db.add(blocked)
    
    db.commit()
    
    log_activity(db, None, "IP_BLOCKED", request.client.host if request else "0.0.0.0",
                request.headers.get("user-agent") if request else None,
                f"Admin: {current_admin.username}, IP: {ip_address}, Hours: {hours}")
    
    return {"success": True, "message": f"IP {ip_address} заблокирован на {hours} часов"}

@app.delete("/api/admin/unblock-ip/{ip_address}")
async def unblock_ip(
    ip_address: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Разблокировка IP адреса"""
    blocked = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
    
    if not blocked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IP адрес не найден в списке блокировок"
        )
    
    db.delete(blocked)
    db.commit()
    
    log_activity(db, None, "IP_UNBLOCKED", request.client.host,
                request.headers.get("user-agent"),
                f"Admin: {current_admin.username}, IP: {ip_address}")
    
    return {"success": True, "message": f"IP {ip_address} разблокирован"}

@app.get("/api/admin/blocked-ips")
async def list_blocked_ips(
    request: Request,
    db: Session = Depends(get_db),
    current_admin: AdminUser = Depends(get_current_admin)
):
    """Список заблокированных IP адресов"""
    blocked_ips = db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()
    
    return {
        "blocked_ips": [
            {
                "id": ip.id,
                "ip_address": ip.ip_address,
                "reason": ip.reason,
                "blocked_at": ip.blocked_at.isoformat(),
                "blocked_until": ip.blocked_until.isoformat() if ip.blocked_until else None,
                "created_by": ip.created_by,
                "is_active": ip.is_active()
            }
            for ip in blocked_ips
        ]
    }

# ==================== ТЕЛЕГРАМ БОТ ИНТЕГРАЦИЯ ====================
@app.post("/api/telegram/webhook")
async def telegram_webhook(
    update: Dict[str, Any],
    request: Request,
    db: Session = Depends(get_db)
):
    """Webhook для Telegram бота"""
    # Валидация токена (если требуется)
    # if request.headers.get("X-Telegram-Bot-Api-Secret-Token") != settings.TELEGRAM_BOT_TOKEN:
    #     raise HTTPException(status_code=401, detail="Unauthorized")
    
    logger.info(f"Telegram webhook received: {update}")
    
    # Здесь можно добавить обработку обновлений от Telegram бота
    # Например, активацию лицензии через бота
    
    return {"ok": True}

# ==================== ИНИЦИАЛИЗАЦИЯ ПРИ ЗАПУСКЕ ====================
@app.on_event("startup")
async def startup_event():
    """Действия при запуске приложения"""
    logger.info("Starting MangaBuff License API...")
    logger.info(f"Environment: {settings.NODE_ENV}")
    logger.info(f"Database: {settings.DATABASE_URL[:30]}...")
    
    # Создание администратора по умолчанию если нет пользователей
    db = SessionLocal()
    try:
        if db.query(AdminUser).count() == 0:
            default_password = secrets.token_urlsafe(16)
            admin = AdminUser(
                username="admin",
                password_hash=hash_password(default_password),
                email="admin@mangabuff.com",
                is_active=True
            )
            db.add(admin)
            db.commit()
            
            logger.info("=" * 60)
            logger.info("ВАЖНО: СОХРАНИТЕ ЭТИ ДАННЫЕ ДЛЯ ВХОДА")
            logger.info("=" * 60)
            logger.info(f"Логин: admin")
            logger.info(f"Пароль: {default_password}")
            logger.info("=" * 60)
            logger.info("Смените пароль сразу после первого входа!")
            
            # Также выводим в консоль для Render логов
            print("=" * 60)
            print("DEFAULT ADMIN CREDENTIALS (SAVE THESE):")
            print("=" * 60)
            print(f"Username: admin")
            print(f"Password: {default_password}")
            print("=" * 60)
    except Exception as e:
        logger.error(f"Error creating default admin: {e}")
        db.rollback()
    finally:
        db.close()

@app.on_event("shutdown")
async def shutdown_event():
    """Действия при остановке приложения"""
    logger.info("Shutting down MangaBuff License API...")

# ==================== ЗАПУСК СЕРВЕРА ====================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 10000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=settings.NODE_ENV == "development",
        workers=1 if settings.NODE_ENV == "development" else 2
    )
