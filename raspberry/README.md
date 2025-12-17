Build
=====
Before compiling the project, you must first create a docker with the necessary toolchain. 
To create a docker, go to the ‘docker’ directory and run ‘build_docker.sh’ script:
```
cd docker
./build_docker.sh
cd ..
```

You can check if the docker is working by running the ‘run.sh’ script.
```
$ ./run.sh 
root@e9b95b7360c5:/# 
```

Try to run compile.sh to see all available arguments:
```   
$ ./compile.sh 
--x86 - compile release for x86 platform.
--arm - cross-compile release for ARM platform.
--clean - cleans all the build files in the project
```

Build the project:
```
$ ./compile.sh --arm
```