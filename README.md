## modular slang

the idea here is just to make something like slangc.exe, but which treats
entrypoints like regular functions.

basics and gotchas

- all functions marked `public` are exported as entrypoints.
- we use a custom build of slang which lets entrypoints use regular arguments
  instead of cbuffers / structs.
- it is intended for use with simple math kernels
  - see `example.slang` for an example. you'd `#include example.hlsl` in the
    rest of some shader and call the public APIs.

usage

- import unitypackage
- right click .slang file, select 'Translate to HLSL'
  - it should also auto recompile whenever you tab back into unity
- import the generated .hlsl in your shader

build instructions

```bash
git clone https://github.com/yum-food/slang
cd slang
git submodule update --init --recursive -j 32
# wait, the previous command takes a while
mkdir build
cd build
powershell.exe cmake.exe ..
powershell.exe cmake.exe --build . -j 32 --config Release
# the previous command will take a long fucking time
# switch back to top level of repo
cd ../..
# do this in wsl2 or powershell. Showing wsl2/bash syntax.
powershell.exe ./build.ps1 && ./dist/modular_slang.exe ./demo.slang
```

