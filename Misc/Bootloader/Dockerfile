FROM debian:latest@sha256:72547dd722cd005a8c2aa2079af9ca0ee93aad8e589689135feaed60b0a8c08d

RUN apt-get update && apt-get install -y \
    qemu-system-arm socat \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /challenge

# Copie des binaires du challenge
COPY u-boot.bin firmware.bin ./

# Scripts de wrapper
COPY entrypoint.sh qemu_wrapper.sh ./
RUN chmod +x entrypoint.sh qemu_wrapper.sh

EXPOSE 4000

CMD ["./entrypoint.sh"]
