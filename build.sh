#!/bin/bash

set -e

clang -ggdb -O2 -shared -fPIC -fPIE -o hook.so dxgk_hook.c
LD_PRELOAD=$PWD/hook.so glxinfo
