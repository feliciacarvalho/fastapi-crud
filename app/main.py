from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext 
from datetime import datetime, timedelta

app = FastAPI()

SECRET_KEY = "desafio"
ALGORITHM = "HS256"
TEMPO_ACESSO_TOKEN = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def cria_jwt_token(data: dict):
    to_encode = data.copy();
    expira = datetime.utcnow() + timedelta(minutes=TEMPO_ACESSO_TOKEN)
    to_encode.update({"exp": expira})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return  encoded_jwt

def decodifica_jwt(token: str = Depends(oauth2_scheme)):
    credencial_except = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail = "Não foi possivel validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise credencial_except

@app.post("/token")
def login_para_acesso(form_data: OAuth2PasswordRequestForm = Depends()):
    #...logica de autenticação
    pass

################### Conection postgres #####################

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, MetaData
from sqlalchemy.orm import declarative_base, Session, sessionmaker, relationship
from databases import Database

DATABASE_URL = "postgresql://user:password@localhost/dbname"

database = Database(DATABASE_URL)
metadata = MetaData()

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Modelo do Usuário
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# Criação das tabelas no banco de dados
Base.metadata.create_all(bind=engine)

#################### CRUD #########################

from sqlalchemy.ext.declarative import declarative_base
from typing import List

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Rotas CRUD
@app.post("/users/", response_model=User)
async def create_user(user: User, db: Session = Depends(get_db)):
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.get("/users/{user_id}", response_model=User)
async def read_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.get("/users/", response_model=List[User])
async def read_users(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    users = db.query(User).offset(skip).limit(limit).all()
    return users

@app.put("/users/{user_id}", response_model=User)
async def update_user(user_id: int, user: User, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Atualiza apenas os campos recebidos
    for var, value in vars(user).items():
        setattr(db_user, var, value) if value else None
    
    db.commit()
    db.refresh(db_user)
    return db_user

@app.delete("/users/{user_id}", response_model=User)
async def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return user