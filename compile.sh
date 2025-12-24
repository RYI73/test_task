#!/bin/bash

result1=0
result2=0

case $1 in
  --arm)
        sh -c './builder.sh --arm'
        result1=$?
    ;;

  --x86)
        sh -c './builder.sh --x86'
        result2=$?
    ;;

  --clean)
        sh -c './builder.sh --clean-arm'
        result1=$?
        sh -c './builder.sh --clean-x86'
        result2=$?
    ;;

  *)
        echo "--x86 - compile release for x86 platform."
        echo "--arm - cross-compile release for ARM platform."
        echo "--clean - cleans all the build files in the project"
    ;;
esac

if [[ $result1 != 0 ]] || [[ $result2 != 0 ]] 
then
    exit 1 # terminate if an error occurs
fi
