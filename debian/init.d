#! /bin/sh

### BEGIN INIT INFO
# Provides:          hpsockd
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: start and stop the HP Socks daemon
# Description:       hpsockd is a Socks Daemon
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/hpsockd
NAME=hpsockd
DESC="HP SOCKS daemon"

test -f $DAEMON || exit 0

set -e

case "$1" in
  start)
	if [ -f /etc/hpsockd.conf ]; then
		echo -n "Starting $DESC: "
		start-stop-daemon --start --quiet --pidfile /var/run/$NAME.pid \
			--exec $DAEMON
		echo "$NAME."
	else
		echo "Not starting $DESC: no config file."
	fi
	;;
  stop)
	echo -n "Stopping $DESC: "
	start-stop-daemon --stop --quiet --pidfile /var/run/$NAME.pid \
		--exec $DAEMON
	echo "$NAME."
	;;
  reload|force-reload)
	echo "Reloading $DESC configuration files."
	/usr/sbin/sdc reload
  ;;
  restart)
	echo -n "Restarting $DESC: "
	start-stop-daemon --stop --quiet --pidfile \
		/var/run/$NAME.pid --exec $DAEMON
	sleep 1
	start-stop-daemon --start --quiet --pidfile \
		/var/run/$NAME.pid --exec $DAEMON
	echo "$NAME."
	;;
  *)
	N=/etc/init.d/$NAME
	echo "Usage: $N {start|stop|restart|reload|force-reload}" >&2
	exit 1
	;;
esac

exit 0
