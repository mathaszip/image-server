from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Header
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

class ProjectRequest(BaseModel):
    project_name: str

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
async def new_project(request: ProjectRequest):
    project_name = request.project_name
    project_folder = os.path.join(UPLOAD_FOLDER, project_name)
    os.makedirs(project_folder, exist_ok=True)

    token = jwt.encode({'project': project_name}, SECRET_KEY, algorithm="HS256")
    return {"token": token}

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    token_data: TokenData = Depends(require_jwt),
    fullUrl: str = Header("true")  # Default to "true" as a string
):
    # Convert the fullUrl parameter to a boolean
    fullUrl = fullUrl.lower() == "true"

    if file and sanitize_file(file):
        file_extension = os.path.splitext(file.filename)[1]
        filename = f"{uuid.uuid4()}{file_extension}"  # Retain the original file extension
        filepath = os.path.join(UPLOAD_FOLDER, token_data.project, filename)
        with open(filepath, "wb") as buffer:
            buffer.write(file.file.read())
        
        if fullUrl:
            return {"url": f"{BASE_URL}/{token_data.project}/{filename}"}
        else:
            return {"filename": filename}
    
    raise HTTPException(status_code=400, detail="Invalid file uploaded")

@app.delete("/delete/{filename}")
async def delete_file(filename: str, token_data: TokenData = Depends(require_jwt)):
    filepath = os.path.join(UPLOAD_FOLDER, token_data.project, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        return {"message": "File deleted"}
    raise HTTPException(status_code=404, detail="File not found")