# xcp-stuff
Home of the XCP-ng infra health check script & misc xcp tooling

## how to use
Run the health.sh script on an XOA appliance with no arguments, it will pull pool/host information from XOA's database.  

If XOA is connected to more than one pool, specify the IP of the pool master you wish to check, otherwise it only checks the first pool listed in XOA. Providing the password is not necessary, it will be pulled from XOA. If the host/pool is not in XOA, you can manually specify the pool master IP and password:
```
[03:34 14] xoa:~$ ./health.sh --help
Usage:
  ./health_test.sh [-f] [-s] [pool_master_or_host[:ssh_port] [root_password]]

  - All parameters are optional
  - If a host is not supplied, the first one from xo-server-db will be used
  - If a password is not supplied, it will be looked up locally in xo-server-db
  - By default, the script runs in pool mode (checks all hosts in the pool)
  - Use '-f' flag to filter output to only show issues found
  - Use '-s' flag to only check the specified host (do not check other pool members if present)

  Examples:
  ./health_test.sh 192.168.1.5
  ./health_test.sh 192.168.1.6 'mypass'
  ./health_test.sh -s 192.168.1.7 'mypass'
  ```