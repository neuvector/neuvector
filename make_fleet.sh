#!/bin/bash

# This script is invoked by build container

echo "==> Unitest"
go test github.com/neuvector/neuvector/share/... || exit $?
go test github.com/neuvector/neuvector/controller/... || exit $?
go test github.com/neuvector/neuvector/agent/... || exit $?

echo "==> Making agent"
cd monitor; make || exit $?; cd ..
cd dp; make || exit $?; cd ..
cd tools/nstools; make || exit $?; cd ../..
cd agent/workerlet/pathWalker; make || exit $?; cd ../../..
cd agent; make || exit $?; cd ..

echo "==> Making controller"
cd controller; make || exit $?; cd ..

exit 0
