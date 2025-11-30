FROM archlinux:latest@sha256:c136b06a4f786b84c1cc0d2494fabdf9be8811d15051cd4404deb5c3dc0b2e57

# Pin to Arch Linux Archive snapshot for reproducibility
# Using snapshot from 2025-11-05 to ensure LLVM 21.1.5-1 availability
RUN echo 'Server = https://archive.archlinux.org/repos/2025/11/05/$repo/os/$arch' > /etc/pacman.d/mirrorlist

# Update system and install required packages
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
    llvm \
    clang \
    make \
    socat \
    && pacman -Scc --noconfirm

# Verify LLVM version (should be 21.1.5-1)
RUN llvm-config --version

# Create challenge user with restricted access
RUN useradd -m -s /bin/bash challenge && \
    chmod 700 /home/challenge

# Set working directory
WORKDIR /home/challenge

# Create bin and src directories
RUN mkdir -p /home/challenge/bin /home/challenge/src

# Copy challenge files
COPY challenge/flag.txt /home/challenge/flag.txt
COPY challenge/Makefile_player /home/challenge/Makefile
COPY challenge/bin/the_maze_of_the_sorcerer.so /home/challenge/bin/the_maze_of_the_sorcerer.so

# Set proper permissions
RUN chown -R challenge:challenge /home/challenge && \
    chmod 644 /home/challenge/flag.txt && \
    chmod 644 /home/challenge/Makefile && \
    chmod 755 /home/challenge/bin/the_maze_of_the_sorcerer.so && \
    chmod 755 /home/challenge/bin && \
    chmod 755 /home/challenge/src

# Copy the runner script
COPY challenge/run_challenge.sh /usr/local/bin/run_challenge.sh
RUN chmod 755 /usr/local/bin/run_challenge.sh

# Copy the service wrapper script
COPY challenge/start_service.sh /start_service.sh
RUN chmod 755 /start_service.sh

# Set environment variable for listen port (can be overridden)
ENV LISTEN_PORT=1337

# Run the service
CMD ["/start_service.sh"]
