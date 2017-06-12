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


def setup_capture(item):
    if item.get_marker('nocapture'):
        return

    storage = item.config.pluginmanager.getplugin('storage').get_storage(item)
    capture = PcapDump(str(storage.join('trace.pcap')), None)
    capture.start()

    policy = item.config.getoption('--pcap-retention')
    capture.preserve = bool(policy == 'always')
    return capture


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    capture = setup_capture(item)
    item.config.capture = capture
    yield
    if capture:
        capture.stop()
        pytest.log.info('{} recieved by filter, '
                        '{} dropped by kernel'.format(*capture.stats))
        if not capture.preserve:
            capture.delete()


def pytest_runtest_makereport(item, call):
    capture = getattr(item.config, 'capture', None)
    if not capture:
        return

    policy = item.config.getoption('--pcap-retention')
    if call.excinfo and policy == 'on-failure':
        item.config.capture.preserve = True


@pytest.fixture
def local_trace(request):
    '''start a pcap trace on the local test machine
    '''
    try:
        return request.config.capture
    except AttributeError:
        pytest.fail('Failed to launch packet capture')


@pytest.hookimpl
def pytest_get_trace(item):
    try:
        return item.config.capture
    except AttributeError:
        pytest.fail('Failed to launch packet capture')


@pytest.hookimpl
def pytest_addhooks(pluginmanager):
    class PcapHooks:
        @pytest.hookspec(firstresult=True)
        def pytest_get_trace(item):
            pass

    pluginmanager.add_hookspecs(PcapHooks())
