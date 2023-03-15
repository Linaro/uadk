
The rsyslog.conf file is the main configuration file for the rsyslogd which logs system
messages on systems. The uadk library can set up the log level and log file by use the rsyslogd.
the uadk log can be printed in message or syslog file default. You can set your own uadk.log
file in rsyslog.conf.

1. If selected the static compilation, the syslog will not be used, The information will be printed
   on the serial port.
2. If not edited the rsyslog.conf, the log files will be printed in /var/log/messages.
3. If you don't want to use the rsyslogd, you can edit the Makefile.am. The information will be
   printed on the serial port.
4. If you want to use the rsyslogd, you can see the following information.

The uadk supports four setting commands, the log level parameters:
   local5.err        # display the error conditions
   local5.info       # display the warning and error conditions
   local5.debug      # display the debug,warning,error conditions
   local5.*          # print levels are not differentiated.

The following steps will help you set up the syslog file:

step 1:
   Add the following information to the last line of /etc/rsyslog.conf:
   local5.err                                         /var/log/uadk.log

step 2:
   Restart the rsyslog daemon service. The cmd is:
   service rsyslog restart

After you run the tasks. You can see the uadk.log in /var/log/uadk/log. If you want to clear the
log file, you can use the following cmd: echo 0 > /var/log/uadk.log.

