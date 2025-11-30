FROM debian:12@sha256:3d957cd5e0693cf44cbb65aa43033fb701443df6b0afa4dcc9293c9bb7a258f9

RUN apt update &&\
apt install -y socat 

RUN apt-get update

RUN useradd --home-dir /home/user --create-home user 
RUN mkdir /home/user/chall

COPY ./bin /home/user/chall/
COPY flag.txt /home/user/chall/
RUN chmod 555 /home/user/chall/bin

WORKDIR /home/user/chall
USER user 

EXPOSE 4444

CMD socat tcp-listen:4444,reuseaddr,fork exec:/home/user/chall/bin

