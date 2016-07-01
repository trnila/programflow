# Program flow
## Build
```sh
$ git clone --recursive https://github.com/trnila/programflow.git
$ cd programflow/
$ make
```

## Usage
```sh
$ ./graph <outputDirectory> <program> <program arguments...>
```
## Example
```sh
$ ./graph /tmp/graph bash -c 'ls | tac | tr a-z A-Z > /dev/null'
$ dot -Tsvg /tmp/graph/graph.dot > /tmp/graph/graph.svg
$ $BROWSER /tmp/graph/graph.svg
```

```sh
$ tree /tmp/graph
/tmp/graph
├── 17303
│   └── pipe:[5947768].out
├── 17304
│   ├── pipe:[5947768].in
│   ├── pipe:[5947769].out
│   ├── tmp-tacZ6LgPK (deleted).in
│   ├── tmp-tacZ6LgPK (deleted).out
│   └── usr-share-locale-locale.alias.in
├── 17305
│   ├── dev-null.out
│   └── pipe:[5947769].in
├── graph.dot
└── graph.svg

3 directories, 10 files
```

### or you can use 
```sh
$ ./do.sh bash -c 'ls | tac | tr a-z A-Z > /dev/null'
```
output graph will be stored in /tmp/graph/graph.svg
