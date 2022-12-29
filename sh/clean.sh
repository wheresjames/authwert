#!/bin/bash

#--------------------------------------------------------------------------------------------------
SCRIPTPATH=$(realpath ${BASH_SOURCE[0]})
SCRIPTDIR=$(dirname $SCRIPTPATH)
ROOTDIR=$(dirname $SCRIPTDIR)
if [[ ! -d "$ROOTDIR" ]]; then
    echo "Invalid script path: ${ROOTDIR}"
    exit -1
fi

#--------------------------------------------------------------------------------------------------
rmFiles()
{
    for v in $1; do
        f="${ROOTDIR}/${v}"
        if [ -f "$f" ]; then
            rm "$f"
        fi
    done
}

rmDirs()
{
    for v in $1; do
        d="${ROOTDIR}/${v}"
        if [ -d "$d" ]; then
            rm -Rf "$d"
        fi
    done
}


#--------------------------------------------------------------------------------------------------
# pypi
#--------------------------------------------------------------------------------------------------

rmDirs "build dist authwert.egg-info"

