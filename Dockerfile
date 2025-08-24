# Use an official Python runtime as a base image
FROM python:3.9-slim-bookworm

# Install system dependencies required for nmap and Python packages
RUN apt-get update && apt-get install -y \
    nmap \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . .

# Create a directory for persistent data
RUN mkdir -p /app/data

# Expose the port the app runs on (Flask default is 5000)
EXPOSE 5000

# Define environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Create a non-root user to run the application
RUN useradd -m sentineluser
RUN chown -R sentineluser:sentineluser /app

# Switch to non-root user for better security
# Note: nmap scanning may require root privileges, so we'll keep using root for now
# USER sentineluser

# Run the application with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "run:app"]
