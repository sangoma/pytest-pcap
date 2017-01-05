import os
import cffi


ffi = cffi.FFI()

ffi.set_source('pytest_pcap._pcap', '''
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <linux/if_ether.h>
#include <pcap/pcap.h>
''', libraries=['pcap'])

here = os.path.dirname(__file__)
with open(os.path.join(here, 'pcap.h'), 'r') as header:
    ffi.cdef(header.read())


if __name__ == '__main__':
    ffi.compile()
