FROM ubuntu:latest as executor

WORKDIR /app

FROM python:3.8-slim-buster

COPY requirements.txt requirements.txt

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update
RUN apt-get -y install gcc

RUN pip3 install -r requirements.txt

COPY . .

RUN sh gen.sh

COPY certs/ca.crt /usr/local/share/ca-certificates/extra/ca.crt
COPY certs/ca.crt /usr/share/ca-certificates/extra/ca.crt
#RUN apk add ca-certificates
RUN update-ca-certificates

CMD [ "python3", "-m" , "proxy"]