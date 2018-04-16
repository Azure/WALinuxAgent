#!/bin/sh

count=0
exitcode=0

while [ $# -gt 0 ]; do
    case "$1" in
	-e)
	    shift
	    echo $1 1>&2
	    shift
	    ;;
	-o)
	    shift
	    echo $1
	    shift
	    ;;
	-t)
	    shift
	    count=$1
	    shift
	    ;;
	-x)
	    shift
	    exitcode=$1
	    shift
	    ;;
	*)
	    break
	    ;;
    esac
done

if [ $count -gt 0 ]; then
    for iter in $(seq 1 $count); do
	sleep 1
	echo "Iteration $iter"
    done
fi

exit $exitcode
