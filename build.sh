
target=$1

if [ "$target" == "test" ]; then 
    CFLAGS="-O0" python ./setup.py build --build-platlib ./test/
fi

if [ "$target" == "release" ]; then
    python ./setup.py build
fi
