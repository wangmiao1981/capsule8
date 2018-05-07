# Known-Issues

- A minimum of Linux kernel version 3.10 is normally required; however, RHEL
kernels (e.g., CentOS 6.6+) that are based on Linux kernel version 2.6.32 have
the perf-related patches backported. Unfortunately, during development there
were issues discovered involving kernel panics. We believe we have worked
around the problems, and our testing has shown the sensor to be stable on these
kernels.
- Linux kernel version 4.13 introduced new security-related functionality that
causes some internal structure layouts to be randomized at compile-time. If
this functionality is enabled, some monitoring performed by the sensor will not
function properly. At this time, we know that Ubuntu distributions deploying
kernel versions 4.13 and newer are not enabling structure layout randomization.
