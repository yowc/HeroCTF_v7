FROM debian:bookworm-20251020@sha256:26f2a7cab45014541c65f9d140ccfa6aaefbb49686c6759bea9c6f7f5bb3d72f

# Install required packages
RUN apt-get update && apt-get install -y \
    software-properties-common \
    python3 \
    python3-dbus \
    dbus \
    openssh-server \
    sudo \
    libevent-dev \
    ncurses-dev \
    build-essential \
    bison \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Build tmux
COPY tmux-3.0a.tar.gz /tmp/tmux-3.0a.tar.gz
RUN tar -zxf /tmp/tmux-3.0a.tar.gz -C /tmp && \
    cd /tmp/tmux-3.0a && \
    ./configure && \
    make && \
    make install && \
    rm -rf /tmp/tmux-3.0a.tar.gz /tmp/tmux-3.0a

# Create users with specific UIDs
RUN adduser --disabled-password --gecos "" --uid 1001 user && \
    echo 'user:password' | chpasswd && \
    ln -sf /dev/null /home/user/.bash_history

RUN adduser --disabled-password --gecos "" --uid 1002 dev && \
    echo 'dev:d4e8f9a2b1c3d5e7f8a9b0c1d2e3f4a5' | chpasswd && \
    ln -sf /dev/null /home/dev/.bash_history

RUN adduser --disabled-password --gecos "" --uid 1004 admin && \
    echo 'admin:9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c' | chpasswd && \
    ln -sf /dev/null /home/admin/.bash_history

RUN adduser --disabled-password --no-create-home --gecos "" --uid 1005 dbus-service && \
    mkdir -p /var/procedures && \
    chown dbus-service:dbus-service /var/procedures && \
    chmod 755 /var/procedures && \
    usermod -d /var/procedures dbus-service

# Set proper permissions on home directories
RUN chmod 700 /home/user /home/dev /home/admin

# Create flags
RUN echo "Hero{1s_1t_tmux_0r_4l13n?_a20bac4b5aa32e8d9a8ccb75d228ca3e}" > /home/dev/flag.txt && \
    chown dev:dev /home/dev/flag.txt && \
    chmod 400 /home/dev/flag.txt

RUN echo "Hero{d0ubl3_rc3_ftw_ad57172613c7d5403a671fd7878a659d}" > /home/admin/flag.txt && \
    chown admin:admin /home/admin/flag.txt && \
    chmod 400 /home/admin/flag.txt

# Create procservice directory
RUN mkdir -p /opt/procservice && \
    chown root:root /opt/procservice && \
    chmod 755 /opt/procservice

# Copy source files
COPY src/procedure-processing-service.py /opt/procservice/procedure-processing-service.py
COPY src/lib/ /opt/procservice/lib/
COPY src/procedure-processing-service.service /etc/systemd/system/procedure-processing-service.service
COPY src/com.system.ProcedureService.conf /etc/dbus-1/system.d/com.system.ProcedureService.conf

# Set permissions - root owns, dbus-service group can read, only root can write
RUN chown -R root:dbus-service /opt/procservice/ && \
    chmod -R 750 /opt/procservice/

# Create /home/dev/procservice_src/ with source code copy for dev user
RUN mkdir -p /home/dev/procservice_src && \
    cp -r /opt/procservice/* /home/dev/procservice_src/ && \
    chown -R dev:dev /home/dev/procservice_src && \
    chmod -R 755 /home/dev/procservice_src

# DBUS config should be readable by all
RUN chmod 644 /etc/dbus-1/system.d/com.system.ProcedureService.conf

# Copy scripts folder to /root
COPY scripts/ /root/
# Compile process_monitor.c to binary
RUN gcc -O2 -Wall -o /root/process_monitor /root/process_monitor.c && \
    rm /root/process_monitor.c && \
    chmod +x /root/start.sh && \
    chmod +x /root/process_monitor && \
    chmod +x /root/monitor_wrapper.sh

# Add sudoers for all users for password-less sudo to themselvess
RUN echo "user ALL=(user) NOPASSWD: ALL\ndev ALL=(dev) NOPASSWD: ALL\nadmin ALL=(admin) NOPASSWD: ALL\ndbus-service ALL=(dbus-service) NOPASSWD: ALL" >> /etc/sudoers

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Expose SSH port
EXPOSE 22

# Set entrypoint
ENTRYPOINT ["/root/start.sh"]

