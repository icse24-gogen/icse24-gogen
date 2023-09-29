#!/usr/bin/env bash
# set -euxo pipefail

name=$1;

# rm -rf output fuzzoutput 

rm -rf result$name;
mkdir result$name;

# afl-go-instrumentor -func=$name -test=true  -o $name.zip -dep=/home/user/workspace/gowork/src/GoFuzz/afl-golang/afl-go-build/afl-go-instrumentor/afl-golang-dep ./;

mv $name.zip result$name;
cd result$name;
unzip $name.zip;
chmod +x afl.exe;

./afl.exe -test.run TestAFLFoo lenconfig;
# Test
AFL_NO_UI=1 AFL_BENCH_DRY_RUN_ONLY=1 mopt-golang-20 -t 100000+ -m 100G -i ./corpus -o Testoutput -s ./corpus/.state/lenconfig/id:000000,lenconfig ./afl.testing -test.run TestAFLFoo @@ @L;

# Fuzz 
AFL_NO_UI=1 timeout 3h  mopt-golang-20 -t 100000+ -m 100G -i ./corpus -o Fuzzoutput -s ./corpus/.state/lenconfig/id:000000,lenconfig ./afl.testing -test.run TestAFLFoo @@ @L;

parsebbmap.py $name ./Fuzzoutput/bb_bitmap ./Testoutput/bb_bitmap > /home/user/tmp/res0405$name;
# coverfunc.py $name > /home/user/tmp/res$name;