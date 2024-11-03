# flask/Dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y libmagic1

# Install Python dependencies
RUN pip install flask python-magic PyJWT

# Set the working directory
WORKDIR /app

# Copy the Flask app code
COPY app.py .

# Create the upload directory
RUN mkdir -p /uploads

# Expose port
EXPOSE 7000

# Start the Flask application
CMD ["python", "app.py"]