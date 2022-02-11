#!/bin/bash

go test github.com/neuvector/neuvector/... || exit $?
