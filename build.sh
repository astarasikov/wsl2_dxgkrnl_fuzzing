#!/bin/bash

set -e

clang -Werror -ggdb -O2 -shared -fPIC -fPIE -o hook.so dxgk_hook.c
while true; do
    LD_PRELOAD=$PWD/hook.so glxgears || true
done
