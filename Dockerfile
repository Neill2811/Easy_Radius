FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/radius-admin

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY easy_radius ./easy_radius

ENV PYTHONUNBUFFERED=1 \
    RADIUS_ADMIN_DATA_DIR=/opt/radius-admin/data \
    RADIUS_ADMIN_USE_NSENTER=1 \
    RADIUS_ADMIN_HOST=0.0.0.0 \
    RADIUS_ADMIN_PORT=8088

EXPOSE 8088

CMD ["python", "-m", "easy_radius"]
