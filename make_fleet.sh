#!/bin/bash

# This script is invoked by build container

echo "==> Unitest"
./unitest.sh || exit $?

echo "==> Making agent"
cd monitor; make || exit $?; cd ..
cd dp; make || exit $?; cd ..
cd tools/nstools; make || exit $?; cd ../..
cd tools/sidekick; make || exit $?; cd ../..
cd agent/workerlet/pathWalker; make || exit $?; cd ../../..
cd agent; make || exit $?; cd ..

echo "==> Making controller"
cd controller; make || exit $?; cd ..

exit 0
