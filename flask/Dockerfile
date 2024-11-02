# flask/Dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y libmagic1 clamav clamav-daemon

# Install Flask and other dependencies
RUN pip install flask python-magic clamd PyJWT

# Set the working directory
WORKDIR /app

# Copy the Flask app code
COPY app.py .

# Create the upload directory
RUN mkdir -p /uploads

# Update ClamAV database and start the ClamAV daemon
RUN freshclam && \
    echo "TCPSocket 3310" >> /etc/clamav/clamd.conf && \
    echo "TCPAddr 0.0.0.0" >> /etc/clamav/clamd.conf

# Expose port
EXPOSE 7000

# Start ClamAV daemon and the Flask application
CMD service clamav-daemon start && python app.py