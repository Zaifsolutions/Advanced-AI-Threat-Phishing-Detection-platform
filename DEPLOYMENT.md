# 🚀 DEPLOYMENT GUIDE

## Advanced Phishing Detection Platform - Production Deployment

---

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [Local Development Setup](#local-development-setup)
3. [Production Deployment](#production-deployment)
4. [Docker Deployment](#docker-deployment)
5. [Cloud Platform Deployment](#cloud-platform-deployment)
6. [Security Hardening](#security-hardening)
7. [Monitoring & Logging](#monitoring--logging)
8. [Troubleshooting](#troubleshooting)

---

## 🖥️ System Requirements

### Minimum (Development)
- **CPU**: Dual-core processor (2GHz+)
- **RAM**: 4GB minimum (8GB recommended)
- **Storage**: 2GB free space
- **Python**: 3.9 or higher
- **OS**: Windows 10+, macOS 10.15+, Linux (Ubuntu 20.04+)

### Recommended (Production)
- **CPU**: 4+ cores (Intel Xeon / AMD EPYC)
- **RAM**: 16GB+ (for ML model loading + concurrent requests)
- **Storage**: 100GB+ SSD
- **Network**: 1Gbps+ connection
- **Load Balancer**: Nginx or HAProxy
- **Reverse Proxy**: Apache / Nginx

---

## 🏠 Local Development Setup

### Step 1: Clone Repository
```bash
git clone https://github.com/Zaifsolutions/Advanced-Phishing-Detection-Platform.git
cd Advanced-Phishing-Detection-Platform
```

### Step 2: Create Python Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
cd Backend
pip install -r requirements.txt
```

### Step 4: Verify Installation
```bash
python -c "import fastapi, sklearn, bs4; print('✅ All dependencies installed successfully')"
```

### Step 5: Run Backend Server
```bash
python main.py
```
Expected output:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
```

### Step 6: Open Frontend
In a new terminal, navigate to Frontend folder:
```bash
cd ../Frontend
python -m http.server 5000
# Open: http://localhost:5000 in browser
```

---

## 🏢 Production Deployment

### Environment Configuration

Create `Backend/.env` file:
```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
RELOAD=False

# Security
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
CORS_CREDENTIALS=True
MAX_FILE_SIZE=52428800  # 50MB in bytes

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/phishing_detection/app.log

# ML Model
MODEL_PATH=./ml_model.pkl
VECTORIZER_PATH=./tfidf_vectorizer.pkl

# Performance
WORKER_TIMEOUT=120
REQUEST_TIMEOUT=30
```

### Gunicorn Setup (Production WSGI Server)

#### Install Gunicorn
```bash
pip install gunicorn
```

#### Create `Backend/gunicorn_config.py`
```python
import multiprocessing

# Server socket
bind = "127.0.0.1:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
timeout = 120
keepalive = 5

# Logging
accesslog = "/var/log/phishing_detection/access.log"
errorlog = "/var/log/phishing_detection/error.log"
loglevel = "info"

# Process naming
proc_name = "phishing-detection-api"

# SSL (if using HTTPS)
# keyfile = "/etc/ssl/private/key.pem"
# certfile = "/etc/ssl/certs/cert.pem"
# ssl_version = "TLSv1_2"
```

#### Start with Gunicorn
```bash
cd Backend
gunicorn -c gunicorn_config.py main:app
```

### Nginx Reverse Proxy Configuration

Create `/etc/nginx/sites-available/phishing-detection`:
```nginx
upstream phishing_api {
    server 127.0.0.1:8000;
    server 127.0.0.1:8001;
    server 127.0.0.1:8002;
}

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;
    
    # SSL Certificate
    ssl_certificate /etc/ssl/certs/yourdomain.crt;
    ssl_certificate_key /etc/ssl/private/yourdomain.key;
    
    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # Compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
    gzip_min_length 1024;
    
    # Frontend
    location / {
        alias /var/www/phishing-detection/Frontend/;
        try_files $uri $uri/ /index.html;
        expires 30d;
    }
    
    # API Proxy
    location /api/ {
        proxy_pass http://phishing_api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_request_buffering off;
        client_max_body_size 50M;
    }
    
    # Health Check
    location /health {
        proxy_pass http://phishing_api/api/health;
        access_log off;
    }
}
```

Enable configuration:
```bash
sudo ln -s /etc/nginx/sites-available/phishing-detection /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

---

## 🐳 Docker Deployment

### Dockerfile

Create `Dockerfile` in project root:
```dockerfile
# Multi-stage build
FROM python:3.11-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libssl-dev \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY Backend/requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ffmpeg \
    libsndfile1 \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application
COPY Backend/ ./Backend/
COPY Frontend/ ./Frontend/

# Copy ML models
COPY ml_model.pkl ./Backend/
COPY tfidf_vectorizer.pkl ./Backend/

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/api/health')"

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "Backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose

Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      - API_HOST=0.0.0.0
      - API_PORT=8000
      - API_WORKERS=4
    volumes:
      - ./Backend:/app/Backend
      - ./Frontend:/app/Frontend
    restart: unless-stopped
    networks:
      - phishing-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
      - ./Frontend:/usr/share/nginx/html:ro
    depends_on:
      - api
    restart: unless-stopped
    networks:
      - phishing-net

networks:
  phishing-net:
    driver: bridge
```

### Build & Run
```bash
# Build image
docker build -t phishing-detection:2.1.0 .

# Run container
docker run -p 8000:8000 phishing-detection:2.1.0

# Or use Docker Compose
docker-compose up -d
```

---

## ☁️ Cloud Platform Deployment

### AWS Deployment

#### Step 1: Create EC2 Instance
```bash
# SSH into instance
ssh -i key.pem ubuntu@your-instance-ip

# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Python & dependencies
sudo apt-get install -y python3.11 python3-pip python3-venv git nginx
```

#### Step 2: Deploy Application
```bash
# Clone repository
git clone https://github.com/Zaifsolutions/Advanced-Phishing-Detection-Platform.git
cd Advanced-Phishing-Detection-Platform

# Setup environment
python3 -m venv venv
source venv/bin/activate
pip install -r Backend/requirements.txt
```

#### Step 3: Create Systemd Service
Create `/etc/systemd/system/phishing-detection.service`:
```ini
[Unit]
Description=Phishing Detection API
After=network.target

[Service]
Type=notify
User=ubuntu
WorkingDirectory=/home/ubuntu/Advanced-Phishing-Detection-Platform
ExecStart=/home/ubuntu/Advanced-Phishing-Detection-Platform/venv/bin/gunicorn -c Backend/gunicorn_config.py Backend.main:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable & start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable phishing-detection
sudo systemctl start phishing-detection
```

### Azure App Service

```bash
# Login to Azure
az login

# Create resource group
az group create -n phishing-rg -l eastus

# Create App Service Plan
az appservice plan create -n phishing-plan -g phishing-rg --sku B2 --is-linux

# Create Web App
az webapp create -n phishing-detection-app -g phishing-rg -p phishing-plan --runtime "PYTHON|3.11"

# Deploy from GitHub
az webapp deployment source config-zip -n phishing-detection-app -g phishing-rg --src archive.zip
```

### Google Cloud Run

```bash
# Authenticate
gcloud auth login

# Build and push image
gcloud builds submit --tag gcr.io/PROJECT_ID/phishing-detection

# Deploy to Cloud Run
gcloud run deploy phishing-detection \
  --image gcr.io/PROJECT_ID/phishing-detection \
  --platform managed \
  --region us-central1 \
  --memory 2Gi \
  --cpu 2 \
  --allow-unauthenticated
```

---

## 🔒 Security Hardening

### 1. API Rate Limiting
Install slowapi:
```bash
pip install slowapi
```

Add to `Backend/main.py`:
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/api/analyze/text")
@limiter.limit("100/minute")
async def analyze_text(request: Request, input: TextInput):
    # ... implementation
```

### 2. HTTPS/TLS Enforcement
```nginx
# Force HTTPS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
```

### 3. WAF (Web Application Firewall)
- AWS WAF rules for common attacks
- ModSecurity rules for Nginx
- DDoS protection via CloudFlare

### 4. Input Validation
```python
# Max file size check
if file.size > 52428800:  # 50MB
    raise HTTPException(status_code=413, detail="File too large")

# File type validation
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.doc', '.docx', '.eml', ...}
```

---

## 📊 Monitoring & Logging

### Prometheus Metrics
```bash
pip install prometheus-client
```

Add to `Backend/main.py`:
```python
from prometheus_client import Counter, Histogram

request_count = Counter('api_requests_total', 'Total API requests')
request_latency = Histogram('api_request_latency_seconds', 'API request latency')

@app.middleware("http")
async def add_metrics(request: Request, call_next):
    request_count.inc()
    start_time = time.time()
    response = await call_next(request)
    request_latency.observe(time.time() - start_time)
    return response
```

### ELK Stack (Elasticsearch, Logstash, Kibana)
```yaml
# docker-compose.yml addition
elk:
  image: docker.elastic.co/elasticsearch/elasticsearch:8.0.0
  environment:
    - discovery.type=single-node
  ports:
    - "9200:9200"
```

---

## 🔧 Troubleshooting

### Issue: Port 8000 Already in Use
```bash
# Find process using port
lsof -i :8000
# Kill process
kill -9 <PID>
# Or use different port
uvicorn Backend.main:app --port 8001
```

### Issue: ML Model Not Loading
```bash
# Check model files exist
ls -la Backend/*.pkl

# Rebuild model
python Backend/ml_trainer.py --rebuild
```

### Issue: CORS Errors in Frontend
Check `ALLOWED_ORIGINS` in environment:
```python
# Backend/main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5000", "https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Issue: High Memory Usage
Monitor with:
```bash
# Linux
top -p $(pgrep -f "uvicorn")

# Adjust workers
workers = (cpu_count * 2) + 1  # In gunicorn_config.py
```

---

## ✅ Post-Deployment Checklist

- [ ] SSL/TLS certificate installed and valid
- [ ] CORS properly configured for production domain
- [ ] Database backups configured (if applicable)
- [ ] Monitoring and alerting setup
- [ ] Rate limiting enabled
- [ ] File upload restrictions enforced
- [ ] Logging infrastructure active
- [ ] Health check endpoint responding
- [ ] API endpoints tested in production
- [ ] Frontend loading correctly
- [ ] No console errors in browser
- [ ] Performance metrics acceptable
- [ ] Security headers present
- [ ] DDoS protection enabled
- [ ] Regular security audits scheduled

---

**For additional support, contact: support@zaifsecurity.pro**
