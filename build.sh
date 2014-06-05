
target=$1

if [ "$target" == "test" ]; then 
    python ./setup.py build --build-platlib ./test/
fi

if [ "$target" == "release" ]; then
    python ./setup.py build
fi
