#!/bin/bash

clang -ggdb -O2 -shared -fPIC -fPIE -o hook.so dxgk_hook.c
