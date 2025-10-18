FROM python:3-slim

WORKDIR /app

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update \
 && apt-get -y install --no-install-recommends git nmap \
 && git clone https://github.com/GamehunterKaan/AutoPWN-Suite.git . \
 && pip install --no-cache-dir -r requirements.txt \
 && apt-get purge -y --auto-remove git \
 && apt-get -y clean all \
 && rm -rf /var/lib/apt/lists/*

ENTRYPOINT [ "python", "autopwn.py" ]
