#!/bin/bash

# This script is invoked by build container

echo "==> Making updater"
cd upgrader; make || exit $?; cd ..

echo "==> Making monitor"
cd monitor; make || exit $?; cd ..

echo "==> Making scanner"
cd scanner; make || exit $?; cd ..
cd scanner/task; make || exit $?; cd ../..
cd scanner/rpmparser; make || exit $?; cd ../..
