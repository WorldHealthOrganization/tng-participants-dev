#!/bin/bash
echo "Start fileCheck"
echo "Check:" $1
find $1 -print | grep -i "Failure" > temp/Failure

if [ -s "temp/Failure" ]; then
    rm "temp/Failure"
fi

find $1 -print | grep -i "CSR" > temp/CSR

if [ -s "temp/CSR" ]; then
    rm "temp/CSR"
fi

find $1 -print | grep -i "signed" > temp/SIGNED

if [ -s "temp/SIGNED" ]; then
    rm "temp/SIGNED"
fi
echo failure
cat temp/Failure
echo csr
cat temp/CSR
echo signed
cat temp/SIGNED
echo "finished fileCheck"
