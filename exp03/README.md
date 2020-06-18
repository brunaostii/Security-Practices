#EXP03

Develop a program that does a bruteforce attack to find the password of a password protected ZIP file.

Your program should expect 2 arguments, -l and -f. -l specifies the dictionary file and -f specifies the ZIP file.

Your program must print to the standard output the following: The password is %s, replacing %s by the actual password. This must be the only thing printed to the standard output.

Consider, for example, your program being executed like this: bruteforce -l /tmp/list.txt -f /tmp/secrets.zip. In this case your program must read the potential passwords from /tmp/list.txt and must find the password of /tmp/secrets.zip.
