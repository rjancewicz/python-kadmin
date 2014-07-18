
target=$1

if [ "$target" == "test" ]; then 
    CFLAGS="-O0" python ./setup.py build --build-platlib ./test/
fi

if [ "$target" == "dist" ]; then 
    python ./setup.py sdist
fi

if [ "$target" == "release" ]; then
    CFLAGS="-O3" python ./setup.py build
fi
