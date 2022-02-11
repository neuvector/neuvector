#!/bin/bash

echo $GOPATH
export GOPATH=$GOPATH:${PWD}
echo $GOPATH
go test ./... || exit $?

