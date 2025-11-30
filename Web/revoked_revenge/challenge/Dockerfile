FROM python:3.11@sha256:df64b825ea3eff541ad1fda26620222d68824e8f3a619b76ebe4b342c4d807ff

WORKDIR /challenge

COPY app/ .

RUN pip3 install -r requirements.txt


RUN groupadd challenge \
    && useradd --no-create-home -d /challenge -g challenge challenge \
    && chown -R challenge:challenge /challenge/ \
    && chmod -R 755 /challenge/

EXPOSE 5000
ENTRYPOINT ["./start.sh"]
