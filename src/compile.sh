#!/bin/bash
current_PATH='./*.cpp'
dcr2cpn_PATH='./dcr2cpn/*.cpp'
ltl2prop_PATH='./ltl2prop/*.cpp'

g++ -c "$dcr2cpn_PATH"  -c "$ltl2prop_PATH" -c "$current_PATH"