# Multi-stage Dockerfile for testing and building steganography app

# Stage 1: Base testing image
FROM python:3.11-slim as test-base

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libffi-dev \
    libssl-dev \
    zlib1g-dev \
    libjpeg-dev \
    libpng-dev \
    ffmpeg \
    xvfb \
    x11-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install test dependencies
RUN pip install --no-cache-dir pytest pytest-cov pytest-xvfb

# Copy application code
COPY . .

# Stage 2: Test runner
FROM test-base as test

# Run tests with coverage
CMD ["pytest", "-v", "--cov=stego", "--cov=gui", "--cov=app", "--cov-report=xml", "--cov-report=term", "tests/"]

# Stage 3: Build stage for executables (PyInstaller)
FROM test-base as build

# Install PyInstaller
RUN pip install --no-cache-dir pyinstaller

# Build CLI executable
RUN pyinstaller --onefile --name stego-cli app.py

# Build GUI executable
RUN pyinstaller --onefile --windowed --name stego-gui gui/main.py

# Stage 4: Final minimal image with executables
FROM python:3.11-slim as final

RUN apt-get update && apt-get install -y \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built executables
COPY --from=build /app/dist/stego-cli /usr/local/bin/
COPY --from=build /app/dist/stego-gui /usr/local/bin/

CMD ["stego-cli", "--help"]
