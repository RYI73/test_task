#!/bin/bash

echo "Compile with UID=${LOCAL_USER_ID} GID=${LOCAL_GROUP_ID} HOME=${LOCAL_HOME_PATH}"

result1=0
result2=0

case $1 in
  --arm)
        docker container run \
        -v $(pwd):/home/pi/ \
        -e "LOCAL_USER_ID=${LOCAL_USER_ID}" \
        -e "LOCAL_USER_NAME=${LOCAL_USER_NAME}" \
        -e "LOCAL_GROUP_ID=${LOCAL_GROUP_ID}" \
        -e "LOCAL_HOME_PATH=${LOCAL_HOME_PATH}" \
            raspberry/pi \
        sh -c '/home/pi/builder.sh --arm'
        result1=$?
    ;;

  --x86)
        sh -c './builder.sh --x86'
        result2=$?
    ;;

  --clean)
        docker container run \
        -v $(pwd):/home/pi \
        -e "LOCAL_USER_ID=${LOCAL_USER_ID}" \
        -e "LOCAL_USER_NAME=${LOCAL_USER_NAME}" \
        -e "LOCAL_GROUP_ID=${LOCAL_GROUP_ID}" \
        -e "LOCAL_HOME_PATH=${LOCAL_HOME_PATH}" \
            raspberry/pi \
        sh -c '/home/pi/builder.sh --clean-arm'
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
