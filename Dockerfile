FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bluephishproxy/ bluephishproxy/
COPY BluePhishProxy.py .

RUN mkdir -p data analytics

EXPOSE 8443

CMD ["gunicorn", "bluephishproxy.app:create_app()", \
     "--bind", "0.0.0.0:8443", \
     "--workers", "4", \
     "--access-logfile", "-"]
