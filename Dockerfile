FROM python:3-slim

WORKDIR /data

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update \
 && apt-get -y install nmap \
 && pip install --no-cache-dir autopwn-suite \
 && apt-get -y clean all

ENTRYPOINT [ "autopwn-suite" ]
