FROM trivialsec/python-base

ARG COMMON_VERSION
ARG PYTHONDEBUG
ARG PYTHONUNBUFFERED
ARG PYTHONUTF8
ARG PYTHONDEVMODE
ARG PYTHONCOERCECLOCALE
ARG CFLAGS
ARG STATICBUILD
ARG LC_ALL
ARG LANG
ARG AWS_ACCOUNT
ARG AWS_REGION
ARG AWS_DEFAULT_REGION
ARG AWS_ACCESS_KEY_ID
ARG AWS_SECRET_ACCESS_KEY
ENV PYTHONDEBUG ${PYTHONDEBUG}
ENV PYTHONUNBUFFERED ${PYTHONUNBUFFERED}
ENV PYTHONUTF8 ${PYTHONUTF8}
ENV PYTHONDEVMODE ${PYTHONDEVMODE}
ENV PYTHONCOERCECLOCALE ${PYTHONCOERCECLOCALE}
ENV LC_ALL ${LC_ALL}
ENV LANG ${LANG}
ENV CONFIG_FILE ${CONFIG_FILE}
ENV AWS_ACCOUNT ${AWS_ACCOUNT}
ENV AWS_REGION ${AWS_REGION}
ENV AWS_DEFAULT_REGION ${AWS_DEFAULT_REGION}
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV FLASK_RUN_PORT ${FLASK_RUN_PORT}
ENV FLASK_DEBUG ${FLASK_DEBUG}
ENV FLASK_ENV ${FLASK_ENV}
ENV PATH ${PATH}:/home/ec2-user/.local/bin

USER root
WORKDIR /srv/app

COPY docker/entrypoint.sh /srv/app/entrypoint.sh
RUN mkdir -p /var/log/uwsgi /var/cache/nginx && \
    touch /tmp/application.log && \
    amazon-linux-extras enable nginx1 >/dev/null && \
    yum install -q -y nginx && \
    yum clean metadata && \
    yum -q -y clean all && \
    setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx && \
    chmod a+x /srv/app/entrypoint.sh && \
    aws s3 cp --only-show-errors s3://trivialsec-assets/dev/${COMMON_VERSION}/api.zip /tmp/trivialsec/api.zip && \
    aws s3 cp --only-show-errors s3://trivialsec-assets/dev/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl \
        /srv/app/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl && \
    aws s3 cp --only-show-errors s3://trivialsec-assets/dev/${COMMON_VERSION}/build.zip /tmp/trivialsec/build.zip && \
    unzip -qo /tmp/trivialsec/build.zip -d /srv/app && \
    unzip -qo /tmp/trivialsec/api.zip -d /tmp/trivialsec && \
    cp -nr /tmp/trivialsec/src/* /srv/app/ && \
    chown -R ec2-user: \
        /srv/app \
        /var/log/uwsgi \
        /var/log/nginx \
        /var/lib/nginx \
        /var/cache/nginx \
        /tmp/trivialsec \
        /tmp/application.log && \
    rm -rf /tmp/trivialsec

USER ec2-user
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/app.ini /srv/app/app.ini
COPY docker/requirements.txt /srv/app/requirements.txt
RUN python3.8 -m pip install -q --user --no-cache-dir --find-links=/srv/app/build/wheel --no-index /srv/app/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl && \
    python3.8 -m pip install -q -U --user --no-cache-dir --isolated -r /srv/app/requirements.txt

ENTRYPOINT ["/srv/app/entrypoint.sh"]
CMD ["/home/ec2-user/.local/bin/uwsgi", "--", "app.ini"]
