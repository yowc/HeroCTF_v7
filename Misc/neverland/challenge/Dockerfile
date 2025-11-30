FROM debian:12-slim@sha256:936abff852736f951dab72d91a1b6337cf04217b2a77a5eaadc7c0f2f1ec1758
ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install openssh-server git sudo -y

# Setup users
RUN adduser --disabled-password --gecos "" intern && \
    echo 'intern:fairy' | chpasswd && \
    ln -sf /dev/null /home/intern/.bash_history

RUN adduser --disabled-password --gecos "" peter && \
    echo 'peter:7ac360a87a3a01de6a4bdbf8ba93d5ad' | chpasswd && \
    ln -sf /dev/null /home/peter/.bash_history

# Copy necessary files
COPY ./app /app
COPY ./scripts /tmp/scripts
RUN mv /tmp/scripts/start.sh /root/start.sh

# Setup the local repo and intern commit script
RUN chown -R peter:peter /app && \
    su peter -c "bash /tmp/scripts/setup-repo.sh" && \
    chmod -R 775 /app && \
    mv /tmp/scripts/commit.sh /opt/commit.sh && \
    chown peter:peter /opt/commit.sh && \
    chmod 775 /opt/commit.sh && \
    echo "intern ALL=(peter) /opt/commit.sh" >> /etc/sudoers && \
    chmod o+x /home/intern

# Add flag
RUN echo "Hero{c4r3full_w1th_g1t_hO0k5_d4dcefb250aa8c2ffabaa57119e3bc42}" > /home/peter/flag.txt

# Cleanup
RUN rm -rf /tmp/scripts

# Start SSH
RUN chmod +x /root/start.sh
EXPOSE 22
CMD ["/root/start.sh"]
