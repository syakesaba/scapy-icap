scapy-icap
==========

ICAP/1.0 protocol Implementaion for scapy (copied code from scapy-http by invernizzi)


Usage
==========

    [root@user ~]$ scapy
    WARNING: No route found for IPv6 destination :: (no default route?)
    Welcome to Scapy (2.2.0-dev)
    >>> scapy
    <module 'scapy' from '/usr/local/lib/python2.7/dist-packages/scapy/__init__.pyc'>
    >>> from os import system
    >>> system("ls /usr/local/lib/python2.7/dist-packages/scapy/contrib/icap.py")
    /usr/local/lib/python2.7/dist-packages/scapy/contrib/icap.py
    0
    >>> load_contrib("icap")
    >>> ICAP
    <class 'scapy.contrib.icap.ICAP'>

