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