# CVE-2016-5195 Exploit - Works with Android6.0-rc1 from the Android-x86 project

Source Code is based on the work from [here](https://github.com/scumjr/dirtycow-vdso). It's modified to work with Android6.0-rc1 from the Android-x86 project.

PoC for [Dirty COW](http://dirtycow.ninja/) (CVE-2016-5195).

This PoC relies on ptrace (instead of `/proc/self/mem`) to patch vDSO. It has a
few advantages over PoCs modifying filesystem binaries:

- no setuid binary required
- SELinux bypass
- no kernel crash because of filesystem writeback

And a few cons:

- architecture dependent (since the payload is written in assembly)
- doesn't work on every Linux version
- subject to vDSO changes



