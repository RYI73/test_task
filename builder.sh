#!/bin/bash

BUILD_DIR_X86=build_x86
BUILD_DIR_ARM=build_arm

case $1 in
  --arm)
        if [ ! -d "$BUILD_DIR_ARM" ]; then
             cmake -B $BUILD_DIR_ARM -DTARGET_PLATFORM=arm -DCMAKE_TOOLCHAIN_FILE=../raspberry/toolchain-rpi-zero.cmake
        fi
        
        cd $BUILD_DIR_ARM
        make
        result=$?
    ;;

  --x86)
        if [ ! -d "$BUILD_DIR_X86" ]; then
             cmake -B $BUILD_DIR_X86 -DTARGET_PLATFORM=x86
        fi
        
        cd ./$BUILD_DIR_X86
        make
        result=$?
    ;;

  --clean-arm)
        if rm -rf $BUILD_DIR_ARM/; then
            echo "Folder $BUILD_DIR_ARM/ was removed successfully."
        else
            echo "[WARN] Folder $BUILD_DIR_ARM/ wasn't removed."
            result=-1
        fi
        result=0
    ;;

  --clean-x86)
        if rm -rf ./$BUILD_DIR_X86/; then
            echo "Folder ./$BUILD_DIR_X86/ was removed successfully."
        else
            echo "[WARN] Folder ./$BUILD_DIR_X86/ wasn't removed."
            result=-1
        fi
        result=0
    ;;

  *)
        echo "--x86 - compile release for x86 platform."
        echo "--arm - cross-compile release for ARM platform."
        echo "--clean-arm - cleans all the ARM build files in the project"
        echo "--clean-x86 - cleans all the x86 build files in the project"
    ;;
esac

if [[ $result != 0 ]]
then
    exit 1 # terminate if an error occurs
fi
