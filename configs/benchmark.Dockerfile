# Example production-style image contract. The coordinator supplies the
# build context at the exact benchmark.lock.json commit.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir \
    Flask==3.1.0 ldap3==2.9.1 requests==2.32.4 \
    gunicorn==23.0.0 elementpath==5.0.3 lxml==6.0.0 PyYAML==6.0.2
RUN chown -R 65532:65532 /app/testfiles
ENV FLASK_DEBUG=0 PYTHONUNBUFFERED=1
USER 65532:65532
CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:8000", "--access-logfile", "-", "app:app"]
