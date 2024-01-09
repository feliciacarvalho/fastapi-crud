# Use uma imagem base que suporte sua aplicação FastAPI
FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8

# Define o diretório de trabalho como /app
WORKDIR /app

# Copia o código do seu projeto para o diretório /app no contêiner
COPY ./ /app

# Instala as dependências do seu projeto
RUN pip install -r requirements.txt

# Comando para iniciar a aplicação quando o contêiner for executado
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
