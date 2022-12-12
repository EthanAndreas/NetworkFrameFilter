#!/bin/bash

# This script is used to run the tests for the project.
make

# Run the tests on all the files in "assets" directory
for file in assets/*
do
    printf "\e[33mTesting $file\e[0m\n"
    ./bin/exe -o $file
done 

