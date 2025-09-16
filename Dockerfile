# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first (to leverage Docker caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Expose app port (adjust if different)
EXPOSE 5000

# Run your app (adjust if your entry point is different)
CMD ["python", "app.py"]
