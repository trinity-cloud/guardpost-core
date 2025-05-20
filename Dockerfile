# Dockerfile for guardpost-core

# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install dependencies
# Copy only requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install uv && \
    uv pip install --system --no-cache-dir -r requirements.txt

# Copy project code
# Copying app directory, alembic config, etc.
# Adjust if your project structure is different
COPY ./app /app/app
COPY ./alembic /app/alembic
COPY alembic.ini /app/alembic.ini
# Add other necessary files/dirs if needed

# Default command (can be overridden by docker-compose)
# Expose port 8000 for the app
EXPOSE 8000

# Default command to run app (useful if running image directly)
# CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"] 