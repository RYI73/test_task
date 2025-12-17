Technical Test Assignment
=========================

Clone this repo:
```
git clone --recurse-submodules https://github.com/RYI73/test_task.git
```

Install esp32:
```
cd esp-idf
./install.sh esp32
. ./export.sh
cd ..
```

Check the version:
```
idf.py --version
```

Build 'esp32_spi_router' project:
```
cd esp32_spi_router
idf.py build
cd ..
```

Build desktop utility 'client':
```
cd desktop
./compile --x86
cd ..
```

Build Raspberry Pi utilities 'proxy' and 'server':
```
cd raspberry
./compile --arm
cd ..
```


