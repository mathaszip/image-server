# main.py
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import os
import uuid
import magic
import jwt
from datetime import datetime, timedelta

app = FastAPI()

UPLOAD_FOLDER = '/uploads'
BASE_URL = "https://images.mrlarsen.xyz/images"
SECRET_KEY = "4bbccaecc24500fffff73d5ddf474b6379b23ba86999e5ca5758021a105afa77"
ALLOWED_IMAGE_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/tiff'}

class TokenData(BaseModel):
    project: str

def sanitize_file(file: UploadFile):
    mime = magic.Magic(mime=True)
    file_type = mime.from_buffer(file.file.read(1024))
    file.file.seek(0)  # Reset file pointer after reading

    if file_type not in ALLOWED_IMAGE_TYPES:
        return False

    return True

def require_jwt(authorization: str = Header(...)):
    try:
        token = authorization.split(" ")[1]
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return TokenData(project=decoded['project'])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        raise HTTPException(status_code=401, detail="Unauthorized")

@app.post("/newproject")
async def new_project():
    project_name = str(uuid.uuid4())
    project_folder = os.path.join(UPLOAD_FOLDER, project_name)
    os.makedirs(project_folder, exist_ok=True)

    token = jwt.encode({'project': project_name, 'exp': datetime.utcnow() + timedelta(days=1)}, SECRET_KEY, algorithm="HS256")
    return {"token": token}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), token_data: TokenData = Depends(require_jwt)):
    if file and sanitize_file(file):
        file_extension = os.path.splitext(file.filename)[1]
        filename = f"{uuid.uuid4()}{file_extension}"  # Retain the original file extension
        filepath = os.path.join(UPLOAD_FOLDER, token_data.project, filename)
        with open(filepath, "wb") as buffer:
            buffer.write(file.file.read())
        return {"url": f"{BASE_URL}/{token_data.project}/{filename}"}
    raise HTTPException(status_code=400, detail="Invalid file uploaded")

@app.delete("/delete/{filename}")
async def delete_file(filename: str, token_data: TokenData = Depends(require_jwt)):
    filepath = os.path.join(UPLOAD_FOLDER, token_data.project, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        return {"message": "File deleted"}
    raise HTTPException(status_code=404, detail="File not found")

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=7000)