# VFS0097 fingerprint identifier

A month of work put into getting the Validity's Fingerprint Sensor to work building it all from the ground up on modern C++.

Requires either gcc or clang with C++20 support, libusb 1.0, and at least openssl 1.1.0

Please check Marco Trevisan (3v1n0) [python-validity](https://github.com/3v1n0/python-validity) or [uunicorn](https://github.com/uunicorn/python-validity) in order to enroll your own fingerprint.

If you are running it on Linux, you may add it as part of your authentication method.
Add the following line before `auth pam_unix.so` into your pam `/etc/pam.d/system-auth`:
```
auth sufficient pam_exec.so # path to the compiled version
```

![screenshot](./vfs0097.jpg)
