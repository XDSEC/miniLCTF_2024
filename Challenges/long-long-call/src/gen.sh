#!/bin/sh
gcc -S main.c -masm=intel -o main.s
python shit.py
gcc -s fxxk.s -o longlongcall