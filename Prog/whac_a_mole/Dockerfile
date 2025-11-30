FROM python:3.11-slim@sha256:e4676722fba839e2e5cdb844a52262b43e90e56dbd55b7ad953ee3615ad7534f

WORKDIR /challenge/

# Install socat only (Python is already included in base image)
RUN apt-get update && \
    apt-get install -y socat libgl1 libglib2.0-0 && \
    rm -rf /var/lib/apt/lists/*

# Copy source code
COPY ./src /challenge

# Create user and group
RUN groupadd ctf && \
    useradd -G ctf --home=/challenge player

# Set permissions and install Python dependencies
RUN chmod 4755 /challenge/challenge.py && \
    chmod 4755 /challenge/entry.sh && \
    pip install --no-cache-dir -r /challenge/requirements.txt

# Expose port (provided by environment variable)
EXPOSE ${LISTEN_PORT}

ENTRYPOINT ["/challenge/entry.sh"]
