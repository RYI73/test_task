#!/bin/bash

BUILD_DIR_X86=build_x86
BUILD_DIR_ARM=build_arm
BUILD_DIR_ESP=esp32-lwip-forward-trace
TOOLCHAIN_DIR_ESP=esp-idf

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

  --esp) 
        cd $TOOLCHAIN_DIR_ESP
        . ./export.sh
        cd -
        cd $BUILD_DIR_ESP
        idf.py build
        result=$?
    ;;

  --flash-esp) 
        cd $TOOLCHAIN_DIR_ESP
        . ./export.sh
        cd -
        cd $BUILD_DIR_ESP
        idf.py flash
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

  --clean-esp)
        cd $TOOLCHAIN_DIR_ESP
        . ./export.sh
        cd -
        cd $BUILD_DIR_ESP
        idf.py clean
        result=0
    ;;

  *)
        echo "--x86 - compile release for x86 platform."
        echo "--arm - cross-compile release for ARM platform."
        echo "--esp - cross-compile release for ESP32 platform."
        echo "--flash-esp - flash image to ESP32 chip."
        echo "--clean-arm - cleans all the ARM build files in the project"
        echo "--clean-x86 - cleans all the x86 build files in the project"
        echo "--clean-esp - cleans all the ESP32 build files in the project"
    ;;
esac

if [[ $result != 0 ]]
then
    exit 1 # terminate if an error occurs
fi
