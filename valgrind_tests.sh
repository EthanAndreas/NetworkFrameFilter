#!/bin/bash

# Run the tests on all the files in "assets" directory
for file in assets/*
do
    printf "\e[33mTesting $file\e[0m\n"
    valgrind ./bin/exe -o $file -v 0
done 

