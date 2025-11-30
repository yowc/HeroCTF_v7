# CTF Challenge - Sleeping Pipe
# Build shellcodes and serve C2 server
FROM archlinux:latest@sha256:c136b06a4f786b84c1cc0d2494fabdf9be8811d15051cd4404deb5c3dc0b2e57

# Update and install dependencies
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
    base-devel \
    mingw-w64-gcc \
    rustup \
    python \
    && pacman -Scc --noconfirm

# Create non-root user
RUN useradd -m -s /bin/bash ctf

# Create directory structure expected by build_all.sh
# From rusty_pool_party/rusty_pool_party, challenge is at ../../sleeping_pipe/challenge
RUN mkdir -p /home/ctf/sleeping_pipe/challenge \
    && mkdir -p /home/ctf/rusty_pool_party/rusty_pool_party

# Copy rusty_pool_party files (Dockerfile is in rusty_pool_party/rusty_pool_party)
COPY --chown=ctf:ctf . /home/ctf/rusty_pool_party/rusty_pool_party/

# Copy sleeping_pipe challenge files (copied into build context by docker_build.sh)
COPY --chown=ctf:ctf sleeping_pipe_challenge /home/ctf/sleeping_pipe/challenge/

# Ensure ctf owns everything (fix any permission issues from COPY)
RUN chown -R ctf:ctf /home/ctf

# Switch to ctf user
USER ctf
WORKDIR /home/ctf/rusty_pool_party/rusty_pool_party

# Initialize rustup for ctf user and add mingw target for Rust cross-compilation
RUN rustup default stable && \
    rustup target add x86_64-pc-windows-gnu

# Run build script
# RUN chmod +x build_all.sh && ./build_all.sh

# Expose ports
# 8000 - File server for rusty_pool_party.exe download
# 8080 - C2 server
EXPOSE 8000 8080

CMD ["./start.sh"]
