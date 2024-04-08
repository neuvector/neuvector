#!/bin/bash

# This script is invoked by build container
machine=$(uname -m)
echo "Machine hardware architecture is \"$machine\""

echo "==> Unitest"
go test github.com/neuvector/neuvector/share/... || exit $?
go test github.com/neuvector/neuvector/controller/... || exit $?
go test github.com/neuvector/neuvector/upgrader/... || exit $?
go test github.com/neuvector/neuvector/agent/... || exit $?

echo "==> Making agent"
cd monitor; make || exit $?; cd ..
if [ "$machine" == "aarch64" ]; then
    cd dp; make -f Makefile_arm64 || exit $?; cd ..
elif [ "$machine" == "x86_64" ]; then
    cd dp; make || exit $?; cd ..
fi
cd tools/nstools; make || exit $?; cd ../..
cd agent/workerlet/pathWalker; make || exit $?; cd ../../..
cd agent; make || exit $?; cd ..

echo "==> Making controller"
cd controller; make || exit $?; cd ..

echo "==> Making upgrader"
cd upgrader; make || exit $?; cd ..

exit 0
