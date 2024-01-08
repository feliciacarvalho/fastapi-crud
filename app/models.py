from pydantic import BaseModel, EmailStr

class CriaUsuario(BaseModel):
    name: str
    email: EmailStr
    password: str

class Usuario(BaseModel):
    id: int
    name: str
    email: EmailStr

class UsuarioUpdate(BaseModel):
    name: str
    email: EmailStr