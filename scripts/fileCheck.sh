find $1 -print | grep -i Failure > temp/Failure

if [-s "temp/Failure"]; then
    rm "temp/Failure"
fi

find $1 -print | grep -i csr > temp/CSR

if [-s "temp/CSR"]; then
    rm "temp/CSR"
fi

find $1 -print | grep -i signed > temp/SIGNED

if [-s "temp/SIGNED"]; then
    rm "temp/SIGNED"
fi
