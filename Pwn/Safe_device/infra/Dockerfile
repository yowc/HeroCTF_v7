FROM debian:13@sha256:8f6a88feef3ed01a300dafb87f208977f39dccda1fd120e878129463f7fa3b8f

RUN apt update -y && apt install -y qemu-system-aarch64 

COPY ./images/Image ./images/rootfs.ext4 ./images/start-qemu.sh /root/

WORKDIR /root/ 

CMD "/root/start-qemu.sh"

