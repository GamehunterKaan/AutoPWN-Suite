FROM python:3-slim

WORKDIR /app

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update \
 && apt-get -y install --no-install-recommends nmap \
 && apt-get -y clean all \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt flask flask-cors

COPY . .

ENV AUTOPWN_WEB_HOST=0.0.0.0
ENV AUTOPWN_WEB_PORT=8080

EXPOSE ${AUTOPWN_WEB_PORT}

ENTRYPOINT ["python", "autopwn.py"]
CMD ["--web"]
