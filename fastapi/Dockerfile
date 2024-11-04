# flask/Dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y libmagic1

# Install Python dependencies
RUN pip install fastapi uvicorn python-magic PyJWT python-multipart

# Set the working directory
WORKDIR /app

# Copy the FastAPI app code
COPY app.py .

# Create the upload directory
RUN mkdir -p /uploads

# Expose port
EXPOSE 7000

# Start the FastAPI application using Uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7000"]