FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY dnspython-pinger.py .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

USER 65532:65532
CMD ["python", "./dnspython-pinger.py"]
