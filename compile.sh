#!/bin/bash

result1=0
result2=0
result3=0

case $1 in
  --arm)
        sh -c './builder.sh --arm'
        result1=$?
    ;;

  --x86)
        sh -c './builder.sh --x86'
        result2=$?
    ;;

  --esp)
        sh -c './builder.sh --esp'
        result2=$?
    ;;

  --flash-esp)
        sh -c './builder.sh --flash-esp'
        result2=$?
    ;;

  --clean)
        sh -c './builder.sh --clean-arm'
        result1=$?
        sh -c './builder.sh --clean-x86'
        result2=$?
        sh -c './builder.sh --clean-esp'
        result3=$?
    ;;

  *)
        echo "--x86 - compile release for x86 platform."
        echo "--arm - cross-compile release for ARM platform."
        echo "--esp - cross-compile release for ESP32 platform."
        echo "--flash-esp - flash image to ESP32 chip."
        echo "--clean - cleans all the build files in the project"
    ;;
esac

if [[ $result1 != 0 ]] || [[ $result2 != 0 ]] || [[ $result3 != 0 ]] 
then
    exit 1 # terminate if an error occurs
fi
