# 0xdeadbeef

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



