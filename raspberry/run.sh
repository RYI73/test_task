#!/bin/bash

docker container run --privileged -v  $(pwd):/home/pi/ -it raspberry/pi /bin/bash 
