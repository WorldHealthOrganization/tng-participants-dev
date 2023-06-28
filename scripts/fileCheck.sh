#!/bin/bash
echo "Start fileCheck"
echo "Check:" $1
find $1 -print | grep -i "Failure" > temp/Failure

if [ -n "temp/Failure" ]; then
    rm "temp/Failure"
fi

find $1 -print | grep -i "CSR" > temp/CSR

if [ -n "temp/CSR" ]; then
    rm "temp/CSR"
fi

find $1 -print | grep -i "signed" > temp/SIGNED

if [ -n "temp/SIGNED" ]; then
    rm "temp/SIGNED"
fi

echo "finished fileCheck"
