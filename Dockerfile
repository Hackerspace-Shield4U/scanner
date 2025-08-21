FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei from binary release (AMD64)
RUN wget -O nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v3.4.7/nuclei_3.4.7_linux_amd64.zip" && \
    unzip nuclei.zip && \
    chmod +x nuclei && \
    mv nuclei /usr/local/bin/nuclei && \
    rm nuclei.zip && \
    which nuclei && \
    nuclei -version

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories
RUN mkdir -p /app/logs /app/nuclei-templates /app/custom-templates

# Set environment variables
ENV PYTHONPATH=/app
ENV NUCLEI_TEMPLATES_PATH=/app/nuclei-templates

# Download Nuclei templates
RUN /usr/local/bin/nuclei -update-templates

# Expose port
EXPOSE 5002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5002/health')"

# Run the application
CMD ["python", "app.py"]