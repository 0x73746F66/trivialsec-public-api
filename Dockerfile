FROM registry.gitlab.com/trivialsec/containers-common/python
LABEL org.opencontainers.image.authors="Christopher Langton"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://gitlab.com/trivialsec/public-api"

ARG COMMON_VERSION
ARG BUILD_ENV
ARG GITLAB_USER
ARG GITLAB_PASSWORD

ENV PYTHONPATH /srv/app
ENV APP_ENV ${APP_ENV}
ENV APP_NAME ${APP_NAME}
ENV AWS_REGION ${AWS_REGION}
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV CONFIG_FILE ${CONFIG_FILE}
ENV LOG_LEVEL ${LOG_LEVEL}
ENV FLASK_DEBUG ${FLASK_DEBUG}
ENV FLASK_ENV ${FLASK_ENV}
ENV FLASK_RUN_PORT ${FLASK_RUN_PORT}

COPY --chown=trivialsec:trivialsec requirements.txt .
RUN echo "Cloning Python Libs Package from Gitlab" \
    && git clone --depth 1 --branch ${COMMON_VERSION} --single-branch https://${GITLAB_USER}:${GITLAB_PASSWORD}@gitlab.com/trivialsec/python-common.git /tmp/trivialsec/python-libs \
    && cd /tmp/trivialsec/python-libs \
    && echo "Installing python-libs" \
    && make install \
    && echo "Pip Install" \
    && python3 -m pip install -q -U --no-cache-dir -r /srv/app/requirements.txt \
    && echo "Clean up..." \
    && rm -rf /tmp/trivialsec

COPY --chown=trivialsec:trivialsec src .
COPY --chown=trivialsec:trivialsec conf/config-${BUILD_ENV}.yaml config.yaml

CMD ["gunicorn", "--config=gunicorn.conf.py"]
