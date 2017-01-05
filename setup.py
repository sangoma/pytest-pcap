from setuptools import setup, find_packages


setup(
    name='pytest-pcap',
    version='0.1',
    description='A pcap capture and analysis plugin for pytest',
    author='Simon Gomizelj',
    author_email='sgomizelj@sangoma.com',
    maintainer='Simon Gomizelj',
    maintainer_email="sgomizelj@sangoma.com",
    url='https://github.com/sangoma/pytest-pcap',
    packages=find_packages(),
    classifiers=['Development Status :: 3 - Alpha',
                 'Intended Audience :: Developers',
                 'License :: OSI Approved :: MIT License',
                 'Operating System :: OS Independent',
                 'Programming Language :: Python',
                 'Programming Language :: Python :: 2.7',
                 'Programming Language :: Python :: 3.4',
                 'Programming Language :: Python :: 3.5',
                 'Programming Language :: Python :: 3.6',
                 'Programming Language :: Python :: Implementation :: CPython',
                 'Programming Language :: Python :: Implementation :: PyPy',
                 'Topic :: Software Development :: Testing',
                 'Topic :: Utilities'],
    extras_require={
        'build': ['pycparser', 'cffi'],
    },
    install_requires=[
        'pytest>=2.6.0',
    ],
    cffi_modules=[
        'pytest_pcap/pcap_build.py:ffi'
    ],
    entry_points={
        'pytest11': ['pytest_pcap = pytest_pcap.plugin']
    }
)
