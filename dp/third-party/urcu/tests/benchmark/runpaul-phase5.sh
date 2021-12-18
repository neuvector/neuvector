# test run after write-size update

sh runpaul-phase1.sh
mkdir runpaul-phase1
mv *.log runpaul-phase1/

sh runpaul-phase2.sh
mkdir runpaul-phase2
mv *.log runpaul-phase2/

sh runpaul-phase4.sh
