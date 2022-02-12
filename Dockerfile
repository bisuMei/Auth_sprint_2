FROM python:3.9.10

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN pip install --upgrade pip
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
COPY run.py /run.py
COPY /patched.py /patched.py

ENV PYTHONPATH "${PYTHONPATH}:/code"

CMD gunicorn --worker-class gevent \
  --workers $WORKERS \
  --bind 0.0.0.0:$PORT_APP \
  patched:app

