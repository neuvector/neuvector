#!/bin/sh

#run all tests

#set to number of active CPUS
#NUM_CPUS=8

#extra options, e.g. for setting affinity on even CPUs :
#EXTRA_OPTS=$(for a in $(seq 0 2 127); do echo -n "-a ${a} "; done)

#ppc64 striding, use with NUM_CPUS=8

#stride 1
#EXTRA_OPTS=$(for a in $(seq 0 2 15); do echo -n "-a ${a} "; done)
#stride 2
#EXTRA_OPTS=$(for a in $(seq 0 4 31); do echo -n "-a ${a} "; done)
#stride 4
#EXTRA_OPTS=$(for a in $(seq 0 8 63); do echo -n "-a ${a} "; done)
#stride 8
#EXTRA_OPTS=$(for a in $(seq 0 16 127); do echo -n "-a ${a} "; done)

#Vary update fraction
#x: vary update fraction from 0 to 0.0001
  #fix number of readers and reader C.S. length, vary delay between updates
#y: ops/s

rm -f runall.log
rm -fr runall.detail.log


echo Executing batch RCU test

DURATION=10
BATCH_ARRAY="1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768 65536
	     131072 262144"
NR_WRITERS=$((${NUM_CPUS} / 2))

rm -f batch-rcu.log

NR_READERS=$((${NUM_CPUS} - ${NR_WRITERS}))
for BATCH_SIZE in ${BATCH_ARRAY}; do
	echo "./runtests-batch.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} -d 0 -b ${BATCH_SIZE} ${EXTRA_OPTS} | tee -a batch-rcu.log" >> runall.log
	./runtests-batch.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} -d 0 -b ${BATCH_SIZE} ${EXTRA_OPTS} | tee -a batch-rcu.log
done

#setting gc each 4096. ** UPDATE FOR YOUR ARCHITECTURE BASED ON TEST ABOVE **
EXTRA_OPTS="${EXTRA_OPTS} -b 32768"

echo Executing update fraction test

DURATION=10
WDELAY_ARRAY="0 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768
              65536 131072 262144 524288 1048576 2097152 4194304 8388608
              16777216 33554432 67108864 134217728"
NR_WRITERS=$((${NUM_CPUS} / 2))

rm -f update-fraction.log

NR_READERS=$((${NUM_CPUS} - ${NR_WRITERS}))
for WDELAY in ${WDELAY_ARRAY}; do
	echo "./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} -d ${WDELAY} ${EXTRA_OPTS} | tee -a update-fraction.log" >> runall.log
	./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} -d ${WDELAY} ${EXTRA_OPTS} | tee -a update-fraction.log
done

#Test scalability :
# x: vary number of readers from 0 to num cpus
# y: ops/s
# 0 writer.

echo Executing scalability test

NR_WRITERS=0
DURATION=10

rm -f scalability.log

for NR_READERS in $(seq 1 ${NUM_CPUS}); do
	echo "./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} ${EXTRA_OPTS}| tee -a scalability.log" >> runall.log
	./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} ${EXTRA_OPTS}| tee -a scalability.log
done


# x: Vary reader C.S. length from 0 to 100 us
# y: ops/s
# 8 readers
# 0 writers

echo Executing reader C.S. length test

NR_READERS=${NUM_CPUS}
NR_WRITERS=0
DURATION=10
#in loops.
READERCSLEN_ARRAY="0 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768 65536 131072 262144 524288 1048576 2097152"

rm -f readercslen.log

for READERCSLEN in ${READERCSLEN_ARRAY}; do
	echo "./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} ${EXTRA_OPTS} -c ${READERCSLEN} | tee -a readercslen.log" >> runall.log
	./runtests.sh ${NR_READERS} ${NR_WRITERS} ${DURATION} ${EXTRA_OPTS} -c ${READERCSLEN} | tee -a readercslen.log
done
