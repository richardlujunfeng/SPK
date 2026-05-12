ARG PY_IMAGE=python:3.10-slim-bookworm

FROM ${PY_IMAGE} AS deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        libgmp-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /wheels
COPY requirements.txt constraints.txt ./
RUN pip install --upgrade pip setuptools wheel \
    && pip wheel --no-cache-dir --wheel-dir=/wheels -r requirements.txt -c constraints.txt

FROM ${PY_IMAGE} AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgmp10 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin runspk
WORKDIR /app
COPY requirements.txt constraints.txt ./
COPY --from=deps /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt -c constraints.txt \
    && rm -rf /wheels
COPY . /app
RUN chown -R runspk:runspk /app
USER runspk
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    SPK_CONTAINER=1
ENTRYPOINT ["python", "main.py"]
