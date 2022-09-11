#!/bin/bash

set -e

clang -Werror -ggdb -O2 -shared -fPIC -fPIE -o hook.so dxgk_hook.c
export LD_PRELOAD=$PWD/hook.so
timeout -k 1 1 glxgears || true
