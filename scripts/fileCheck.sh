#!/bin/bash
echo "Start fileCheck"
echo "Check:" $1
find $1 -print | grep -i "Failure" > temp/tmpFailure

if [ -s "temp/tmpFailure" ]; then
    cat temp/tmpFailure > temp/Failure
    rm "temp/tmpFailure"
fi

find $1 -print | grep -i "CSR" > temp/tmpCSR

if [ -s "temp/tmpCSR" ]; then
    cat temp/tmpCSR > temp/CSR
    rm "temp/tmpCSR"
fi

find $1 -print | grep -i "signed" > temp/tmpSIGNED

if [  -s "temp/tmpSIGNED" ]; then
    cat temp/tmpSIGNED > temp/SIGNED
    rm "temp/tmpSIGNED"
fi
ls temp
echo "finished fileCheck"
