SSLLog - analyze Sonicwall SSL portal log files
===============================================

This Perl script reads a syslog created Sonicwall SSL VPN device logfile and
attempts to summarise usage of the Sonicwall SSL VPN gateway.

The script takes two input parameters:
*   input logfile 
*   logtype to summarise on

Output is sent to stdout and can be redirected to e.g. generate emails (as we
did when we still used the Sonicwall SSL gateway).



