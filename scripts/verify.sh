gpg --import temp/gpg  2> /dev/null
cd repo
(cat ../temp/tag | xargs git verify-tag --raw 2> >(grep "GOODSIG"))>../temp/verifyResult
cd ..
gpg --list-keys --with-colons | grep fpr| awk 'NR % 2== 0' | awk -F ':' '{print $10}' | xargs gpg --batch --yes --delete-keys
