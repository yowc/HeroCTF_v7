FROM debian:bookworm-slim@sha256:936abff852736f951dab72d91a1b6337cf04217b2a77a5eaadc7c0f2f1ec1758
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    python3-pip \
    openssh-server \
    sudo \
    iptables \
    vim \
    netcat-traditional \
 && rm -rf /var/lib/apt/lists/*

COPY start.sh /root/start.sh
COPY w_iptables.sh /opt/w_iptables.sh
RUN chmod +x /root/start.sh && \
    chmod +x /opt/w_iptables.sh

WORKDIR /challenge
COPY src/ .
RUN pip3 install -r requirements.txt --break-system-packages
RUN chmod 750 /challenge

RUN adduser --disabled-password --gecos "" aragorn && \
    echo 'aragorn:hobbit' | chpasswd && \
    ln -sf /dev/null /home/aragorn/.bash_history && \
    echo "aragorn ALL=(root) /opt/w_iptables.sh" >> /etc/sudoers

EXPOSE 22 80
ENTRYPOINT ["/root/start.sh"]