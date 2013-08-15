#!/bin/bash

bison -y -o getdate.c getdate.y

python setup.py build_ext --inplace

