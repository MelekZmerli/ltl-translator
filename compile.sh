#!/bin/bash
src_PATH='./src/*.o'
include_PATH='../include/*.o'
input_FILE='unfolding.cpp'
output_FILE="unfolding"

g++ "$input_FILE" "$src_PATH" "$include_PATH" -o "$output_FILE"