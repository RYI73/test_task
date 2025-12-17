#!/bin/bash

usage() {
    echo "Usage: $0 [--bit-capacity|-b BITCAP] [--gcc-version|-g GCC_VER] [--pi-version|-p PI_VER] [--gcc-vendor|-v GCC_VENDOR]"
    echo "  --bit-capacity, -b BITCAP   Set target bit capacity (32|64)"
    echo "  --gcc-version, -g GCC_VER   Set GCC version you want to compile: (7.1.0|7.2.0|7.3.0|7.4.0|7.5.0|8.1.0|8.2.0|8.3.0|9.1.0|9.2.0|9.3.0|9.4.0|10.1.0|10.2.0|10.3.0)"
    echo "  --pi-version, -p PI_VER     What's yours Target Raspberry Pi type (0-1|2-3|3+)"
    echo "  --gcc-vendor, -v GCC_VENDOR What's yours Target Raspberry Pi OS type: (stretch|buster|bullseye) "
    echo "  --clean, -c                 Clean current docker image"
    echo "  --cache-clean, -a           Clean docker build cache"
    echo "  --debug, -d                 Run docker builder in debug mode"
    echo "  --help, -h                  Print help"
    exit 1
}
      
bit_capacity="32"
gcc_version="10.3.0"
pi_version="3+"
gcc_vendor="buster"
mode=""

OPTIONS=$(getopt -o b:g:p:v:cda --long bit-capacity:,gcc-version:,pi-version:,gcc-vendor:,clean,cache-clean,debug,help -- "$@")
if [ $? -ne 0 ]; then
    usage
fi

eval set -- "$OPTIONS"

# Parse args
while true; do
    case "$1" in
        -b|--bit-capacity)
            bit_capacity="$2"
            shift 2
            ;;
        -g|--gcc-version)
            gcc_version="$2"
            shift 2
            ;;
        -p|--pi-version)
            pi_version="$2"
            shift 2
            ;;
        -v|--gcc-vendor)
            gcc_vendor="$2"
            shift 2
            ;;
        -d|--debug)
            mode="debug"
            shift 
            ;;
        -c|--clean-image)
            mode="clean"
            shift 
            ;;
        -a|--clean-cache)
            mode="cache"
            shift 
            ;;
        -h|--help)
            usage
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Invalid option: $1"
            usage
            ;;
    esac
done

case $mode in
  clean)
        docker rmi -f raspberry/pi
    ;;

  cache)
        docker builder prune
    ;;

  debug)
        docker build \
        -t raspberry/pi \
        --progress plain \
        --no-cache \
        --build-arg bit_capacity=$bit_capacity \
        --build-arg gcc_version=$gcc_version \
        --build-arg pi_version=$pi_version \
        --build-arg gcc_vendor=$gcc_vendor \
        . 
    ;;

  *)
        docker build \
        -t raspberry/pi \
        --build-arg bit_capacity=$bit_capacity \
        --build-arg gcc_version=$gcc_version \
        --build-arg pi_version=$pi_version \
        --build-arg gcc_vendor=$gcc_vendor \
        . 
    ;;
esac


