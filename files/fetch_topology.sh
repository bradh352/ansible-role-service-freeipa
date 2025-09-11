#!/bin/bash

if [ "$#" != "1" ] ; then
  echo "must provide suffix"
  exit 1
fi

suffix=$1

server_pairs=`ipa topologysegment-find ${suffix} | grep -E "^  (Left|Right) node:.*" | cut -d ":" -f 2 | sed -e 's/ //g' | sed 'N;s/\n/,/'`

echo "["

first=1
for pair in $server_pairs ; do
  left=`echo $pair | cut -d, -f1`
  right=`echo $pair | cut -d, -f2`
  if [ "$first" != "1" ] ; then
    echo ","
  fi
  first=0
  echo -n "  [ \"${left}\", \"${right}\" ]"
done

echo ""
echo "]"
