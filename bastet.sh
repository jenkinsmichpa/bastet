# Bastet, a netcat activity detector for CNIT 470
# by jenkinsmichpa inspired by theif-adj / aeris salus / cardea scripts

discbinBastet='/home/cnit470g45/discbin/discbin <DISCORD WEBHOOK HERE>'
packetSource='/captures/captureFile*'
localNetwork='10.51.<GROUP NUMBER HERE>.0/24'
netcatProtocol='tcp'
netcatPort='9999'

faces=('ฅ(=ዎܫዎ=)∫' 'ฅ^•ﻌ•^ฅ.' '(=ᓀᆽᓂ=)' 'ฅ ( ◕ ﻌ ◕ )')

touch -a bastet.log
touch -a bastet.err
touch -a bastet.res

for file in $packetSource; do

  previousCompleteResults=$(grep "${file} complete" bastet.res)
  if [ -n "$previousCompleteResults" ]; then
    continue
  fi

  badKitties=$(tshark -r "$file" -Y "ip.dst==${localNetwork} && ${netcatProtocol}.dstport == ${netcatPort}" 2> bastet.err | awk '//') # me and subshells have trust issues

  if [[ $badKitties =~ $netcatPort ]]; then
    echo pawsitive "$file" complete >> bastet.res
    echo "$badKitties" >> bastet.log
    
    rand=$(( RANDOM % 4 ))
    echo "Mwow? Netcat reverse shell activity detected in ${file}!" "${faces[$rand]}" | $discbinBastet
    
    echo "$badKitties" | $discbinBastet
  else
    echo nyagative "$file" complete >> bastet.res
  fi

done

sed -i '/incomplete/d' bastet.res
sed -i '$s/complete/incomplete/' bastet.res
