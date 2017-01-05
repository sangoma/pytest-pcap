# pytest-pcap

Launch a packet capture along side your tests. Comes with two backends:
tcpdump background process and a libpcap background thread.

Also has some initial work for dissecting packets from pure python.

Not fit for general use yet...

# TODO

- look to the dpkt project and see how much overlap there is or
  usefulness

- remove the reliance on the 'storage' plugin. That is an internal
  "fork" of the tmpdir support, and something we need to try and
  upstream, release, or remove/make optional.

- remove the pytest.log (also internal), and replace it with a proper
  terminal report.

- release the analysis code that's built on this for validating SIP/RTP
  post test runs.
