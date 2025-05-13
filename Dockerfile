FROM python:3.11-slim

WORKDIR /app

# Copy requirements first for better caching
COPY deployment-requirements.txt .
RUN pip install --no-cache-dir -r deployment-requirements.txt

# Copy application code
COPY . .

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

# Expose the port
EXPOSE 5000

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--reuse-port", "--workers", "4", "main:app"]