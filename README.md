## modular slang

the idea here is just to make something like slangc.exe, but which treats
entrypoints like regular functions.

basics and gotchas

- all functions marked `public` are exported as entrypoints.
- we use a custom build of slang which lets entrypoints use regular arguments
  instead of cbuffers / structs.
- it should "just work" for simple math kernels

usage

- import unitypackage
- right click .slang file, select 'Translate to HLSL'
  - it should also auto recompile whenever you tab back into unity
- import the generated .hlsl in your shader

build instructions

```bash
git clone https://github.com/shader-slang/slang
cd slang
git checkout 8f499fbe9baf68ef880da2ffe4812fbed1e5c1fa
patch -p1 <../slang.patch
git submodule update --init --recursive -j 32
# wait, the previous command takes a while
mkdir build
cd build
# run this part in powershell, from ./slang/build
cmake.exe ..
cmake.exe --build . -j 32 --config Release
# the previous command will take a long fucking time
# switch back to top level of repo
cd ../..
# do this in wsl2 or powershell. Showing wsl2/bash syntax.
powershell.exe ./build.ps1 && ./dist/modular_slang.exe ./demo.slang
```

