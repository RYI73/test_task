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

Build Raspberry Pi utilities 'proxy' 'client' and 'server':
```
./compile --arm
./compile --x86
```

Build 'esp32_spi_router' project:
```
./compile --esp
```

Flash 'esp32_spi_router' project:
```
./compile --flash-esp
```



