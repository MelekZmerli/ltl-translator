#!/bin/bash
lna_PATH='./test/EtherGame.lna'
context_PATH='./test/test.xml'
context_TYPE="DCR"
ltl_PATH='./test/ltl.json'
sol_ast_PATH='./test/blindAuction.ast'
lna_json_PATH='./test/etherGame.json'
im_json_PATH="./test/test.im.json"
output_PATH='./output/'
output_NAME='test'

./unfolding --lna "$lna_PATH" --context "$context_PATH" --context-type "$context_TYPE" --ltl "$ltl_PATH" --sol-ast "$sol_ast_PATH" --lna-json "$lna_json_PATH" --im-json "$im_json_PATH" --output_path "$output_PATH" --output_name "$output_NAME"

#cmd -k