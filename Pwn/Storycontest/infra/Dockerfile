FROM ubuntu:24.04@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

RUN apt-get update && \
    apt-get install -y libc6 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --home-dir /home/storycontest --create-home storycontest
RUN mkdir -p /home/storycontest/chall

WORKDIR /home/storycontest/chall

COPY storycontest flag.txt ./

RUN chmod 555 /home/storycontest/chall/storycontest && \
    chmod 400 /home/storycontest/chall/flag.txt && \
    chown -R storycontest:storycontest /home/storycontest

EXPOSE 5555

USER storycontest

CMD ["/home/storycontest/chall/storycontest"]
