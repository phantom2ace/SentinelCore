# Use an official Python runtime as a base image
FROM python:3.9-slim-bookworm

# Install system dependencies required for nmap and Python packages
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port the app runs on (Flask default is 5000)
EXPOSE 5000

# Define environment variable for Flask
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Run the application when the container launches
CMD ["flask", "run", "--host=0.0.0.0"]
