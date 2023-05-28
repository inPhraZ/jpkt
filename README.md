# jpkt (JSON packet)

C library that provides network packets to the User Application in JSON format.

## Requirements
- libpcap
- json-glib

## Build
#### CMake
```console
$ git clone https://github.com/inPhraZ/jpkt.git
$ cd jpkt
$ mkdir build && cd build
$ cmake ..
$ make -j$(nproc)
```

### make
```console
$ git clone https://github.com/inPhraZ/jpkt.git
$ cd jpkt
$ make -j$(nproc)
```
