FROM python:3.7-alpine3.10

RUN apk update && apk upgrade
RUN apk add --update \
    build-base \
    libffi-dev \
    libressl-dev \
    python3 \
    python3-dev \
  && pip3 install virtualenv

ENV VIRTUALENV=/opt/venv
RUN python3 -m virtualenv --python=/usr/bin/python3 $VIRTUALENV
ENV PATH="$VIRTUALENV/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY main.py .
ENTRYPOINT [ "python", "main.py" ]

