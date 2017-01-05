# vim:ts=4:sw=4:softtabstop=4:smarttab:expandtab
#
# Copyright (C) 2015 Sangoma Technologies Corp.
# All Rights Reserved.

import pytest
from .dump import PcapDump


def pytest_addoption(parser):
    group = parser.getgroup('pcap capture')
    group.addoption('--pcap-retention', action='store', default='always',
                    choices=['always', 'never', 'on-failure'],
                    help="set a retention policy on all pcap captures")


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    if item.get_marker('nocapture'):
        item.config.capture = None
        return

    storage = item.config.pluginmanager.getplugin('storage').get_storage(item)
    capture = PcapDump(str(storage.join('trace.pcap')), None)
    capture.start()

    policy = item.config.getoption('--pcap-retention')
    capture.preserve = bool(policy == 'always')
    item.config.capture = capture


@pytest.hookimpl(trylast=True)
def pytest_runtest_teardown(item, nextitem):
    # Stop the capture at the end of each test. We'll decide if we
    # want to keep it in a later hook because fixture cleanup still
    # happens after this point.
    capture = getattr(item.config, 'capture', None)
    if capture:
        capture.stop()
        pytest.log.info('{} recieved by filter, '
                        '{} dropped by kernel'.format(*capture.stats))


def pytest_runtest_makereport(item, call):
    capture = getattr(item.config, 'capture', None)
    if not capture:
        return

    policy = item.config.getoption('--pcap-retention')
    if call.excinfo and policy == 'on-failure':
        item.config.capture.preserve = True


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    yield
    capture = getattr(item.config, 'capture', None)
    if capture and not capture.preserve:
        capture.delete()


@pytest.fixture
def local_trace(request):
    '''start a pcap trace on the local test machine
    '''
    try:
        return request.config.capture
    except AttributeError:
        pytest.fail('Failed to launch packet capture')
