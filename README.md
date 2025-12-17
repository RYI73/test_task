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

Build Raspberry Pi utilities 'proxy' 'client' and 'server':
```
./compile --arm
./compile --x86
```


