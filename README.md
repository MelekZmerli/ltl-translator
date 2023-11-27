# unfolding

```
➜ ./app/unfolding --help
Unfolding tool
Usage: ./app/unfolding [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  --lna TEXT:FILE REQUIRED    LNA file (.lna), output of solidity2cpn tools
  --context TEXT:FILE
                              CONTEXT file (.xml), context of model
  --context-type TEXT REQUIRED
                              Context type (DCR,CPN,...)
  --ltl TEXT:FILE REQUIRED    LTL file (.json), Vulnerabilities to check
  --sol-ast TEXT:FILE REQUIRED
                              AST file (.ast), output of solidity compiler in mode --ast-json
  --lna-info TEXT:FILE REQUIRED
                              JSON file (.json), output of solidity2cpn tool
  --im TEXT:FILE REQUIRED
                              JSON file (.json), initial marking settings
  --output_path TEXT          Output file path
  --output_name TEXT          Output file name
```

## Build

The dependencies for this tool are:

- `cmake >= 3.13`
- `doxygen`
- `g++`
- `graphviz`

The tool can be compiled as follows:

```
cmake -S . -B build
cmake --build build --target doxygen --target install
```

## Running

An example of execution is

```
./bin/unfolding \
  --sol-ast ./test/etherGame/etherGame.ast \
  --lna ./test/etherGame/etherGame.lna \
  --lna-info ./test/etherGame/etherGame.json \
  --im ./test/etherGame/initialMarking.json \
  --context-type CPN \
  --context ./test/etherGame/context.lna \
  --ltl ./test/etherGame/formula.json \
  --output-path ./output/ \
  --output-name test
```
