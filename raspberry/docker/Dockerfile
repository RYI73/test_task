FROM debian:10

MAINTAINER Ruslan Valovyi
ENV GIT_REPO el_garden

#Build Debian dependencies
RUN apt-get -y update && apt-get -y upgrade && apt-get install -y build-essential \
    -y git \
    -y gettext \
    -y flex \
    -y bison \
    -y autoconf \
    -y libtool \
    -y automake \
    -y pkg-config \
    -y cmake \
    -y gawk \
    -y gcc \
    -y g++ \
    -y gperf \
    -y flex \
    -y texinfo  \
    -y gfortran \
    -y build-essential \
    -y openssl \ 
    -y unzip \
    -y wget \
    -y pigz \
    -y libncurses-dev \
    -y tar \
    -y figlet \
    -y ccache \
    -y rsync

ARG bit_capacity
ARG gcc_version
ARG pi_version
ARG gcc_vendor

RUN mkdir -p /opt/cross/cross-pi-gcc

COPY Toolchain-RaspberryPi.cmake /opt/cross/Toolchain-RaspberryPi.cmake

#COPY cross-gcc-10.3.0-pi_3+.tar.gz /root/
#RUN /bin/bash -c 'tar -xzvf /root/cross-gcc-*.tar.gz -C /root/ \
#    && CROSS_DIR_LIST="$(ls /root/)" \
#    && for d in $CROSS_DIR_LIST; do \
#          echo "Iteratoin: $d"; \
#          if [[ $d == cross-pi-gcc* ]] ; then \ 
#              TOOLCHAIN_DIR_NAME=$d; break; \              
#          fi; \
#       done  \
#    && cp -r /root/$TOOLCHAIN_DIR_NAME/* /opt/cross/cross-pi-gcc/ \
#    && rm -rf /root/*.tar.gz \
#    && rm -rf /root/$TOOLCHAIN_DIR_NAME \
#    && cd / && rm -rf /tmp/* '

ENV PATH "$PATH:/usr/lib/ccache"

RUN /bin/bash -c '/usr/sbin/update-ccache-symlinks \
    && export CCACHE_COMPRESS=1 \
    && export CCACHE_DIR=$HOME/.ccache \
    && cd /tmp && git clone https://github.com/abhiTronix/raspberry-pi-cross-compilers.git \
    && CMD1="chmod +x ./RTBuilder_"$bit_capacity"b" \
    && CMD2="./RTBuilder_"$bit_capacity"b -g "$gcc_version" -r "$pi_version" -o "$gcc_vendor" -V" \
    && cd /tmp/raspberry-pi-cross-compilers/build-scripts && $CMD1 && $CMD2 \
    && tar -xzvf /root/cross-gcc-*.tar.gz -C /root/ \
    && CROSS_DIR_LIST="$(ls /root/)" \
    && for d in $CROSS_DIR_LIST; do \
          if [[ $d == cross-pi-gcc* ]] ; then \ 
              TOOLCHAIN_DIR_NAME=$d; break; \              
          fi; \
       done  \
    && cp -r /root/$TOOLCHAIN_DIR_NAME/* /opt/cross/cross-pi-gcc/ \
    && rm -rf /root/*.tar.gz \
    && rm -rf /root/$TOOLCHAIN_DIR_NAME \
    && cd / && rm -rf /tmp/* '

ENV PATH "$PATH:/opt/cross/cross-pi-gcc/bin:/opt/cross/cross-pi-gcc/lib:/opt/cross/cross-pi-gcc/include"

RUN cd /tmp && git clone https://github.com/guillemj/libmd.git \
    && cd /tmp/libmd && ./autogen && ./configure --host=arm-linux-gnueabihf && make \
    && cp -P /tmp/libmd/src/.libs/libmd.a /opt/cross/cross-pi-gcc/lib/ \
    && cp -P /tmp/libmd/src/.libs/libmd.so* /opt/cross/cross-pi-gcc/lib/ \
    && cp /tmp/libmd/include/md5.h /opt/cross/cross-pi-gcc/include/ \
    && cd / && rm -rf /tmp/*

RUN cd /tmp && git clone https://gitlab.freedesktop.org/libbsd/libbsd.git \
    && cd /tmp/libbsd && ./autogen \
    && ./configure --host=arm-linux-gnueabihf LDFLAGS=-L/opt/cross/cross-pi-gcc/lib CFLAGS=-I/opt/cross/cross-pi-gcc/include \
    && make \
    && cp -P /tmp/libbsd/src/.libs/libbsd.a /opt/cross/cross-pi-gcc/lib/ \
    && cd / && rm -rf /tmp/*

RUN cd /tmp && git clone https://github.com/json-c/json-c.git \
    && cd /tmp/json-c && cmake -B json-c-build -DCMAKE_TOOLCHAIN_FILE=/opt/cross/Toolchain-RaspberryPi.cmake  \
    && cd /tmp/json-c/json-c-build && make  \
    && cp -P /tmp/json-c/json-c-build/libjson-c.a /opt/cross/cross-pi-gcc/lib/ \
    && mkdir -p /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/json-c-build/json.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/json-c-build/json_config.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/arraylist.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/debug.h /opt/cross/cross-pi-gcc/include/json-c  \
    && cp /tmp/json-c/json_c_version.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/json_object.h /opt/cross/cross-pi-gcc/include/json-c  \
    && cp /tmp/json-c/json_inttypes.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/json_types.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/printbuf.h /opt/cross/cross-pi-gcc/include/json-c  \
    && cp /tmp/json-c/json_object_iterator.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/json_patch.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/json_pointer.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/json_tokener.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/json_util.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/json_visit.h /opt/cross/cross-pi-gcc/include/json-c \
    && cp /tmp/json-c/linkhash.h /opt/cross/cross-pi-gcc/include/json-c \
    && cd / && rm -rf /tmp/*

ENV PATH "$PATH:/opt/cross/cross-pi-gcc/include/json-c"

RUN cd /tmp && git clone https://github.com/joan2937/pigpio.git \
    && cd /tmp/pigpio && make CROSS_PREFIX=arm-linux-gnueabihf- \
    && cp -P /tmp/pigpio/libpigpio.so* /opt/cross/cross-pi-gcc/lib/  \
    && cp -P /tmp/pigpio/libpigpiod_if*.so* /opt/cross/cross-pi-gcc/lib/  \
    && cp /tmp/pigpio/pigpio.h /opt/cross/cross-pi-gcc/include/ \
    && cd / && rm -rf /tmp/*
