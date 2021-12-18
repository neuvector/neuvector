#!/bin/sh

#run all tests

#set to number of active CPUS
export NUM_CPUS=8

#extra options, e.g. for setting affinity on even CPUs :
#EXTRA_OPTS=$(for a in $(seq 0 2 127); do echo -n "-a ${a} "; done)

#ppc64 striding, use with NUM_CPUS=8

rm -f *.log

#stride 1
export EXTRA_OPTS=$(for a in $(seq 0 2 15); do echo -n "-a ${a} "; done)
sh subphase4.sh $*
mkdir ppc64-8cores-stride1
mv *.log ppc64-8cores-stride1/


#stride 2
export EXTRA_OPTS=$(for a in $(seq 0 4 31); do echo -n "-a ${a} "; done)
sh subphase4.sh $*
mkdir ppc64-8cores-stride2
mv *.log ppc64-8cores-stride2/


#stride 4
export EXTRA_OPTS=$(for a in $(seq 0 8 63); do echo -n "-a ${a} "; done)
sh subphase4.sh $*
mkdir ppc64-8cores-stride4
mv *.log ppc64-8cores-stride4/


#stride 8
export EXTRA_OPTS=$(for a in $(seq 0 16 127); do echo -n "-a ${a} "; done)
sh subphase4.sh $*
mkdir ppc64-8cores-stride8
mv *.log ppc64-8cores-stride8/
