## modular slang

the idea here is just to make something like slangc.exe, but which doesn't
require an entrypoint.

basics and gotchas

- all functions marked `public` are exported as entrypoints.
  - this causes slang to put their arguments in a cbuffer. we post-process them
    to fix this.
- any autodiff function calls within a module must *not* be to `public` APIs.
  - this is a consequence of the prior point. any public API is seen by slang
    as an "entrypoint" which accepts a cbuffer argument. the autodiff logic
    does not handle this edge case, so it tries to pass arguments to a function
    which takes no arguments.

build instructions

```bash
git clone https://github.com/shader-slang/slang
git submodule update --init --recursive -j 32
# wait, the previous command takes a while
mkdir slang/build
cd slang/build
# run this part in powershell, from ./slang/build
cmake.exe ..
cmake.exe --build . -j
# the previous command will take a long fucking time
# switch back to top level of repo
cd ../..
# do this in wsl2 or powershell. Showing wsl2/bash syntax
# you'd do this for each incremental build.
powershell.exe ./build.ps1 && ./build/bin/Release/modular_slange.exe ./test.slang
```


