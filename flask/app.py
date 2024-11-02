# flask/app.py
from flask import Flask, request, jsonify
import os
import uuid
import magic
import jwt
import datetime
import clamd

app = Flask(__name__)
UPLOAD_FOLDER = '/uploads'
BASE_URL = "https://images.mrlarsen.xyz/images"
SECRET_KEY = "4bbccaecc24500fffff73d5ddf474b6379b23ba86999e5ca5758021a105afa77"

def sanitize_file(file):
    # Use python-magic to check the file type
    mime = magic.Magic(mime=True)
    file_type = mime.from_buffer(file.read(1024))
    file.seek(0)  # Reset file pointer after reading

    if not file_type.startswith('image/'):
        return False

    # Scan the file for viruses
    cd = clamd.ClamdNetworkSocket('localhost', 3310)
    result = cd.instream(file)
    file.seek(0)  # Reset file pointer after reading

    if result['stream'][0] == 'OK':
        return True
    return False

def require_jwt(func):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
                decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                request.project = decoded['project']
                return func(*args, **kwargs)
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                return jsonify({"error": "Unauthorized"}), 401
        else:
            return jsonify({"error": "Unauthorized"}), 401
    wrapper.__name__ = func.__name__
    return wrapper

@app.route('/newproject', methods=['POST'])
def new_project():
    project_name = request.json.get('project')
    if not project_name:
        return jsonify({"error": "Project name is required"}), 400

    project_folder = os.path.join(UPLOAD_FOLDER, project_name)
    os.makedirs(project_folder, exist_ok=True)

    token = jwt.encode({'project': project_name}, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token}), 200

@app.route('/upload', methods=['POST'])
@require_jwt
def upload_file():
    file = request.files['file']
    project = request.project

    if file and sanitize_file(file):
        filename = f"{uuid.uuid4()}.jpg"  # Assuming the file is an image
        filepath = os.path.join(UPLOAD_FOLDER, project, filename)
        file.save(filepath)
        return jsonify({"url": f"{BASE_URL}/{project}/{filename}"}), 200
    return jsonify({"error": "Invalid file uploaded"}), 400

@app.route('/delete/<filename>', methods=['DELETE'])
@require_jwt
def delete_file(filename):
    project = request.project

    filepath = os.path.join(UPLOAD_FOLDER, project, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        return jsonify({"message": "File deleted"}), 200
    return jsonify({"error": "File not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7000)