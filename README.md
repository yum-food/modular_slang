## modular slang

the idea here is just to make something like slangc.exe, but which doesn't
require an entrypoint.

basics and gotchas

- all functions marked `public` are exported as entrypoints.
- we use a custom build of slang which lets entrypoints use regular arguments
  instead of cbuffers / structs.
- it should "just work" for simple math kernels

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


