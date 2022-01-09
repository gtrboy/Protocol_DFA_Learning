dotFile=$1
output=$2
tmpFile="./tmp.dot"


sed -e "/ERROR/d" "$dotFile" > "$tmpFile"
sed -e "s/TIMEOUT/-/" "$tmpFile" > "$output"
rm -f $tmpFile