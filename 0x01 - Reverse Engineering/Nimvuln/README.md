# Nimvuln

This is a simple script put together in a few hours to perform a check against CVE-2020-8010, CVE-2020-8011, and CVE-2020-8012. Very unlikely to crash the nimcontroller, in order to test CVE-2020-8012, we temporarily overwrite a section of the returned packet. This will not result in a crash.

In the event the target is running linux, nimvuln will attempt to obtain the nimcontroller version. Assume any version under 9.2 is affected and manually perform testing.

```
root@kali:~# python3 nimvuln.py 
usage: nimvuln.py [-h] [-iL INPUT_FILE] [-t TARGET] [-p PORT]

Nimvuln - Scanner for CVE-2020-8010, CVE-2020-8011, and CVE-2020-8012

optional arguments:
  -h, --help            show this help message and exit
  -iL INPUT_FILE, --input-file INPUT_FILE
                        input file containing IP's to be tested
  -t TARGET, --target TARGET
                        use this to query a single host
  -p PORT, --port PORT  target port
```

# Usage

Usage is simple, either read from a list or scan a single target.

![alt text](https://github.com/wetw0rk/CA-UIM-Nimbus-Research/blob/master/0xFF%20-%20Screenshots/Tools/vulnChecker.png)
