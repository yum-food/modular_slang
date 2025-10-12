if (Test-Path -Path ./build) {
  rm -Recurse ./build
}
mkdir ./build

cmake -S . -B build -G "Visual Studio 17 2022" -A x64
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cmake --build build --config Release -j 32
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Package up into ./dist dir
if (Test-Path -Path ./dist) {
  rm -Recurse ./dist
}
mkdir ./dist
cp -Recurse build/bin/Release/* dist
cp -Recurse ./Scripts ./dist/

if (Test-Path -Path ../Assets/yum_food/3ner/Modular_Slang) {
  rm -Recurse ../Assets/yum_food/3ner/Modular_Slang
}
cp -Recurse ./dist ../Assets/yum_food/3ner/Modular_Slang/

