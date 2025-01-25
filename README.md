# ez-server
A multithreaded server written from scratch in GNU C 23. It is completely ready for production -- here are some mind-blowing features:
* Support for up to 1 kilobyte of data transfer per request
* Not backed by a large corporation
    * Probably no NSA backdoors
* Lightweight -- no external libraries (other than the standard POSIX ones)
    * No bloated TLS/SSL implementations
    * Custom, blazingly fast implementation of the HTTP protocol directly on top of POSIX sockets
    * Only HTTP/1.1 support
        * No bloated status messages with each response code
    * Example project is directly integrated into the `src/` directory, reducing filesystem footprint
* Low probability of memory leaks and segmentation faults

## Getting Started
Run `./ez.sh` and figure it out. I don't have time for this.