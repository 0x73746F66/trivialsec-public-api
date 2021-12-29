FROM docker.io/library/python:3.9-slim
LABEL org.opencontainers.image.authors="Christopher Langton"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://gitlab.com/trivialsec/public-api"

ARG PYTHONUTF8
ARG PYTHONUNBUFFERED
ARG LC_ALL
ARG LANG
ARG CFLAGS
ARG STATICBUILD
ARG TRIVIALSEC_PY_LIB_VER
ARG BUILD_ENV
ARG GITLAB_USER
ARG GITLAB_PASSWORD

ENV PYTHONUTF8 ${PYTHONUTF8}
ENV PYTHONUNBUFFERED ${PYTHONUNBUFFERED}
ENV LC_ALL ${LC_ALL}
ENV LANG ${LANG}
ENV CFLAGS ${CFLAGS}
ENV STATICBUILD ${STATICBUILD}
ENV PATH "${PATH}:/srv/app/.local/bin"
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONPATH /srv/app
ENV APP_ENV ${APP_ENV}
ENV APP_NAME ${APP_NAME}
ENV AWS_REGION ${AWS_REGION}
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV LOG_LEVEL ${LOG_LEVEL}
ENV FLASK_DEBUG ${FLASK_DEBUG}
ENV FLASK_ENV ${FLASK_ENV}
ENV FLASK_RUN_PORT ${FLASK_RUN_PORT}

WORKDIR /srv/app
RUN echo "Preparing folders..." && \
    mkdir -p /var/log/gunicorn \
            /usr/share/man/man1mkdir \
            /usr/share/man/man1 && \
    echo "Creating user and group..." && \
    addgroup trivialsec && \
    adduser --disabled-password --gecos '' --disabled-login --home /srv/app --ingroup trivialsec trivialsec && \
    echo "Patching..." && \
    apt-get update -q && \
    apt-get upgrade -qy && \
    echo "Installing Dependencies..." && \
    apt-get install -qy --no-install-recommends \
        build-essential git wget curl bash jq openjdk-11-jdk tar zip \
        ldnsutils logrotate ca-certificates openssl nmap libssl-dev \
        python3-dev default-mysql-client && \
    python3 -m pip install -q --no-cache-dir --no-warn-script-location -U pip && \
    chown -R trivialsec:trivialsec /srv/app /var/log/gunicorn && \
    echo "Clean up..." && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /tmp/* /var/lib/apt/lists/*

USER trivialsec
COPY --chown=trivialsec:trivialsec requirements.txt .
RUN python3 -m pip install -q --no-cache-dir --no-warn-script-location -U setuptools wheel pipx && \
        pipx install awscli && \
        pipx install gunicorn \
    && echo "Cloning Python Libs Package from Gitlab" \
    && git clone -q -c advice.detachedHead=false --depth 1 --branch ${TRIVIALSEC_PY_LIB_VER} --single-branch https://${GITLAB_USER}:${GITLAB_PASSWORD}@gitlab.com/trivialsec/python-common.git /tmp/trivialsec/python-libs \
    && cd /tmp/trivialsec/python-libs \
    && echo "Installing python-libs" \
    && make install \
    && echo "Pip Install" \
    && python3 -m pip install -q -U --no-cache-dir -r /srv/app/requirements.txt \
    && echo "Clean up..." \
    && rm -rf /tmp/trivialsec

COPY --chown=trivialsec:trivialsec src .
CMD ["gunicorn", "--config=gunicorn.conf.py"]
