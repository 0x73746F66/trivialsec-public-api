#!/bin/bash -xe
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
/usr/sbin/nginx -t
echo '* * * * * root /bin/pgrep nginx || /usr/sbin/nginx >/tmp/application.log 2>&1' > /etc/cron.d/nginx-up
echo "* * * * * ec2-user /bin/pgrep uwsgi || /home/ec2-user/.local/bin/uwsgi --listen $(cat /proc/sys/net/core/somaxconn) --daemonize -- /srv/app/app.ini >/tmp/application.log 2>&1" > /etc/cron.d/uwsgi-up
lsof -i :80 -i :8080
