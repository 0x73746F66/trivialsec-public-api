#!/bin/bash -xe
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
runuser -l ec2-user -c 'time /home/ec2-user/.local/bin/uwsgi --listen $(cat /proc/sys/net/core/somaxconn) --daemonize -- /srv/app/app.ini'
lsof -i :80 -i :8080
/usr/sbin/nginx -t
/usr/sbin/nginx || /usr/sbin/nginx -s reopen
