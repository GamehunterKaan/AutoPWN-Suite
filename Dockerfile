FROM python:3-slim

WORKDIR /data

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update \
 && apt-get -y install --no-install-recommends nmap \
 && pip install --no-cache-dir autopwn-suite \
 && apt-get -y clean all \
 && rm -rf /var/lib/apt/lists/*

ENTRYPOINT [ "autopwn-suite" ]
