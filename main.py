import datetime
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- НАСТРОЙКИ ---
# Вставьте сюда вашу строку подключения из MongoDB Atlas (или "mongodb://localhost:27017" если запустите локально)
MONGO_URL = "mongodb+srv://elenamelicenta_db_user:<db_password>@cluster0.zahx9er.mongodb.net/?appName=Cluster0"
SECRET_KEY = "SUPER_SECRET_KEY_DONT_SHARE_IT"  # В реальном проекте прячут в .env
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="FastAPI Mongo Auth")

# Подключение к БД
client = AsyncIOMotorClient(MONGO_URL)
db = client["my_app_database"]
users_collection = db["users"]

# Хеширование и JWT
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- СХЕМЫ ДАННЫХ (Pydantic) ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    email: EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось проверить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = await users_collection.find_one({"email": email})
    if user is None:
        raise credentials_exception
    return user

# --- ЭНДПОИНТЫ (API) ---

@app.post("/register", response_model=UserResponse, status_code=201)
async def register(user_data: UserRegister):
    # Проверяем, существует ли пользователь
    existing_user = await users_collection.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email уже зарегистрирован")
    
    # Хешируем пароль и сохраняем
    hashed_pwd = hash_password(user_data.password)
    new_user = {"email": user_data.email, "hashed_password": hashed_pwd}
    await users_collection.insert_one(new_user)
    
    return {"email": user_data.email}

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Ищем пользователя в БД
    user = await users_collection.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Неверный email или пароль")
    
    # Создаем токен
    access_token = create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/secret-data")
async def get_secret_data(current_user: dict = Depends(get_current_user)):
    return {
        "message": f"Привет, {current_user['email']}! Это секретные данные из базы.",
        "status": "Успешно авторизован"
    }