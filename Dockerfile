# Shared Python 3.14 environment for repeatable verification and Linux builds.
FROM python:3.14-slim AS test-base

ENV CI="" REQUIRE_TK="1"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    zlib1g-dev \
    libjpeg-dev \
    libpng-dev \
    ffmpeg \
    tk \
    xvfb \
    x11-utils \
    xauth \
    libxkbcommon-x11-0 \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-randr0 \
    libxcb-render-util0 \
    libxcb-xinerama0 \
    libxcb-xfixes0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && python -m pip install --no-cache-dir pytest pytest-cov

COPY . .

FROM test-base AS test

CMD ["sh", "scripts/run-tests-xvfb.sh", "pytest", "-v", "--cov=stego", "--cov=gui", "--cov=app", "--cov-report=xml", "--cov-report=term", "tests/"]

FROM test-base AS build

RUN python -m pip install --no-cache-dir "pyinstaller>=6.20,<7"
RUN python -m PyInstaller --noconfirm --clean --onefile --paths . --collect-all imageio_ffmpeg --name stego-cli app.py
RUN python -m PyInstaller --noconfirm --clean --onefile --windowed --paths . --collect-all imageio_ffmpeg --collect-all tkinterdnd2 --name stego-gui gui/main.py

FROM python:3.14-slim AS final

RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg tk \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/dist/stego-cli /usr/local/bin/
COPY --from=build /app/dist/stego-gui /usr/local/bin/

CMD ["stego-cli", "--help"]
