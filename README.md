[![Build Status on Travis CI](https://travis-ci.org/katahiromz/EntryPointExamer.svg?branch=master)](https://travis-ci.org/katahiromz/EntryPointExamer)
[![Build status on AppVeyor](https://ci.appveyor.com/api/projects/status/ww820cb8jcbin41q?svg=true)](https://ci.appveyor.com/project/katahiromz/entrypointexamer)

# epx --- EntryPointExamer by katahiromz

This software examinates whether the specified Windows program can start up correctly on a specific OS by checking the entry points.

## USAGE

### (1)

```txt
epx --os-info win98se.info myfile.exe
```

It examinates whether the file "myfile.exe" can start up on Windows 98 SE.

### (2)

```txt
epx --os-info mywinos.info
```

It dumps the current OS info to the file "mywinos.info".

---
katayama.hirofumi.mz@gmail.com
