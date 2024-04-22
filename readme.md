# Simple Block Device Driver
Implementation of Linux Kernel 5.4.X simple block device.

Note: sysfs interface is used to define target block devices separated by space, tab or comma.
   Target devices can be set at run-time. If there are more than 1 device is set, IO will be forwaded
   to all of them (RAID 1)
   for example: echo "/dev/loop1 /dev/loop2" > /sys/block/sbdd/target_device_path
   If empty string is sent to target_device_path, forwarding will be stoped and IO will go to the memory
   echo "" > /sys/block/sbdd/target_device_path



## Build
- regular:
`$ make`
- with requests debug info:
uncomment `CFLAGS_sbdd.o := -DDEBUG` in `Kbuild`

## Clean
`$ make clean`

## References
- [Linux Device Drivers](https://lwn.net/Kernel/LDD3/)
- [Linux Kernel Development](https://rlove.org)
- [Linux Kernel Teaching](https://linux-kernel-labs.github.io/refs/heads/master/labs/block_device_drivers.html)
- [Linux Kernel Sources](https://github.com/torvalds/linux)
