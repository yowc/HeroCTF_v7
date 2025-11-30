FROM debian:13

RUN apt update -y && apt install -y qemu-system-aarch64

COPY ./images/Image ./images/rootfs.ext4 ./images/start-qemu.sh /root/

WORKDIR /root/ 

CMD "/root/start-qemu.sh"

