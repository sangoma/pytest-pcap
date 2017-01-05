import os
import re
import select
import threading
import errno
import Queue
from subprocess import Popen, PIPE, CalledProcessError
from .pcap import Pcap, MAXIMUM_SNAPLEN


class Dump(object):
    def __init__(self, filename, bpf_program, device=None):
        self.filename = filename
        self.bpf_program = bpf_program
        self.device = device or 'any'
        self.stats = 0, 0

    def delete(self):
        self.stop()
        os.remove(self.filename)


class PcapDump(Dump):
    '''Creates an background thread which uses libpcap directly to
    capture packets on the specified device with the specified bpf
    program.
    '''
    def __init__(self, filename, bpf_program, device=None):
        super(PcapDump, self).__init__(filename, bpf_program, device)
        self._thread = None

    def _capture(self):
        with Pcap.open_live(self.device, MAXIMUM_SNAPLEN, -1, 1000) as pcap:
            if self.bpf_program:
                pcap.setfilter(self.bpf_program)

            pcap.nonblocking = True
            epoll = select.epoll()
            epoll.register(pcap.fileno(), select.EPOLLIN)

            with pcap.dumper(self.filename) as dumper:
                while not self._stop_event.is_set():
                    for _, event in epoll.poll(timeout=1):
                        if event & select.EPOLLIN:
                            dumper.dispatch()
                dumper.dispatch()

            self._queue.put(pcap.stats)

    def start(self):
        '''Start the background thread for the capture.'''
        if self.is_alive:
            raise RuntimeError("dump is already running!")

        self._stop_event = threading.Event()
        self._queue = Queue.Queue()
        self._thread = threading.Thread(target=self._capture)
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        '''Stop the capture.'''
        if self.is_alive:
            self._stop_event.set()
            self._thread.join()
            self.stats = self._queue.get()

    @property
    def is_alive(self):
        '''Check if the capture is currently running.'''
        return self._thread is not None and self._thread.is_alive()


class TcpDump(Dump):
    '''Creates an background tcpdump dump process to capture packets on
    the specified device with the specified bpf program.
    '''

    def __init__(self, filename, bpf_program, device=None):
        super(TcpDump, self).__init__(filename, bpf_program, device)
        self.process = None

    @property
    def is_alive(self):
        '''Check if the tcpdump is currently running.'''
        return self.process and self.process.poll() is None

    def start(self):
        '''Start the background tcpdump process.'''
        if self.is_alive:
            raise RuntimeError("tcpdump is already running!")

        argv = ['tcpdump',
                '-i', self.device,
                '-w', self.filename]

        if self.bpf_program:
            argv.append(self.bpf_program)
        self.process = Popen(argv, stdout=PIPE, stderr=PIPE)

    def stop(self):
        'Stop the running progress tcpdump process'
        if not self.process:
            return

        try:
            self.process.terminate()
            stdout, stderr = self.process.communicate()
        except OSError as e:
            if e.errno == errno.ESRCH:
                raise OSError(e.errno, "Capture was already stopped")
            raise e
        finally:
            retcode = self.process.returncode
            self.process = None

        if retcode:
            raise CalledProcessError(retcode, 'tcpdump')

        match = re.search('(\d+) packets received by filter\n'
                          '(\d+) packets dropped by kernel', stderr)
        if match:
            self.stats = int(match.group(1)), int(match.group(2))
