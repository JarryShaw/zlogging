================================================
ZLogging - Bro/Zeek logging framework for Python
================================================

    Online documentation is available at https://zlogging.readthedocs.io/

The ``ZLogging`` module provides an easy-to-use bridge between the logging
framework of the well-known Bro/Zeek Network Security Monitor (IDS).

    As of version 3.0, the ``Bro`` project has been officially renamed to
    ``Zeek``. [1]_

It was originally developed and derived from the |BroAPT|_ project, which is an
APT detection framework based on the Bro/Zeek IDS and extended with highly
customised and customisable Python wrappers.

.. _BroAPT: https://github.com/JarryShaw/BroAPT
.. |BroAPT| replace:: ``BroAPT``

------------
Installation
------------

.. note::

    ``ZLogging`` supports Python all versions above and includes **3.6**

.. code:: python

    pip install zlogging

-----
Usage
-----

Currently ``ZLogging`` supports the two builtin formats as supported by the
Bro/Zeek logging framework, i.e. ASCII and JSON.

A typical ASCII log file would be like::

    #separator \x09
    #set_separator	,
    #empty_field	(empty)
    #unset_field	-
    #path	http
    #open	2020-02-09-18-54-09
    #fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types
    #types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	string	count	count	count	string	count	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]
    1581245648.761106	CSksID3S6ZxplpvmXg	192.168.2.108	56475	151.139.128.14	80	1	GET	ocsp.sectigo.com	/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFEML0g5PE3oabJGPJOXafjJNRzPIBBSNjF7EVK2K4Xfpm/mbBeG4AY1h4QIQfdsAWJ+CXcbhDVFyNWosjQ==	-	1.1	com.apple.trustd/2.0	-	0	471	200	OK	-	-	(empty)	-	-	-	-	-	-	FPtlyEAhcf8orBPu7	-	application/ocsp-response
    1581245651.379048	CuvUnl4HyhQbCs4tXe	192.168.2.108	56483	23.59.247.10	80	1	GET	isrg.trustid.ocsp.identrust.com	/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFG/0aE1DEtJIYoGcwCs9Rywdii+mBBTEp7Gkeyxx+tvhS5B1/8QVYIWJEAIQCgFBQgAAAVOFc2oLheynCA==	-	1.1	com.apple.trustd/2.0	-	0	1398	200	OK	-	-	(empty)	-	-	-	-	-	-	FRfFoq3hSZkdCNDf9l	-	application/ocsp-response
    1581245654.396334	CWo4pd1z97XLB2o0h2	192.168.2.108	56486	23.59.247.122	80	1	GET	isrg.trustid.ocsp.identrust.com	/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFG/0aE1DEtJIYoGcwCs9Rywdii+mBBTEp7Gkeyxx+tvhS5B1/8QVYIWJEAIQCgFBQgAAAVOFc2oLheynCA==	-	1.1	com.apple.trustd/2.0	-	0	1398	200	OK	-	-	(empty)	-	-	-	-	-	-	FvQehf1pRsGmwDUzJe	-	application/ocsp-response
    1581245692.728840	CxFQzh2ePtsnQhFNX3	192.168.2.108	56527	23.59.247.10	80	1	GET	isrg.trustid.ocsp.identrust.com	/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFG/0aE1DEtJIYoGcwCs9Rywdii+mBBTEp7Gkeyxx+tvhS5B1/8QVYIWJEAIQCgFBQgAAAVOFc2oLheynCA==	-	1.1	com.apple.trustd/2.0	-	0	1398	200	OK	-	-	(empty)	-	-	-	-	-	-	FIeFj8WWNyhA1psGg	-	application/ocsp-response
    1581245701.693971	CPZSNk1Y6kDvAN0KZ8	192.168.2.108	56534	23.59.247.122	80	1	GET	isrg.trustid.ocsp.identrust.com	/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFG/0aE1DEtJIYoGcwCs9Rywdii+mBBTEp7Gkeyxx+tvhS5B1/8QVYIWJEAIQCgFBQgAAAVOFc2oLheynCA==	-	1.1	com.apple.trustd/2.0	-	0	1398	200	OK	-	-	(empty)	-	-	-	-	-	-	F0fGHe4RPuNBhYWNv6	-	application/ocsp-response
    1581245707.848088	Cnab6CHFOprdppKi5	192.168.2.108	56542	23.59.247.122	80	1	GET	isrg.trustid.ocsp.identrust.com	/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFG/0aE1DEtJIYoGcwCs9Rywdii+mBBTEp7Gkeyxx+tvhS5B1/8QVYIWJEAIQCgFBQgAAAVOFc2oLheynCA==	-	1.1	com.apple.trustd/2.0	-	0	1398	200	OK	-	-	(empty)	-	-	-	-	-	-	FgDBep1h7EPHC8qQB6	-	application/ocsp-response
    1581245952.784242	CPNd6t3ofePpdNjErl	192.168.2.108	56821	176.31.225.118	80	1	GET	tracker.trackerfix.com	/announce?info_hash=y\x82es"\x1dV\xde|m\xbe"\xe5\xef\xbe\x04\xb3\x1fW\xfc&peer_id=-qB4210-0ZOn5Ifyl*WF&port=63108&uploaded=0&downloaded=0&left=3225455594&corrupt=0&key=6B23B036&event=started&numwant=200&compact=1&no_peer_id=1&supportcrypto=1&redundant=0	-	1.1	-	-	0	0	307	Temporary Redirect	-	-	(empty)	-	-	-	-	-	-	-	-	-
    1581245960.123295	CfAkwf2CFI13b24gqf	192.168.2.108	56889	176.31.225.118	80	1	GET	tracker.trackerfix.com	/announce?info_hash=!u7\xdad\x94x\xecS\x80\x89\x04\x9c\x13#\x84M\x1b\xcd\x1a&peer_id=-qB4210-i36iloGe*QT9&port=63108&uploaded=0&downloaded=0&left=1637966572&corrupt=0&key=ECE6637E&event=started&numwant=200&compact=1&no_peer_id=1&supportcrypto=1&redundant=0	-	1.1	-	-	0	0	307	Temporary Redirect	-	-	(empty)	-	-	-	-	-	-	-	-	-
    #close	2020-02-09-19-01-40

Its corresponding JSON log file would be like::

    {"ts": 1581245648.761106, "uid": "CSksID3S6ZxplpvmXg", "id.orig_h": "192.168.2.108", "id.orig_p": 56475, "id.resp_h": "151.139.128.14", "id.resp_p": 80, "trans_depth": 1, "method": "GET", "host": "ocsp.sectigo.com", "uri": "/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFEML0g5PE3oabJGPJOXafjJNRzPIBBSNjF7EVK2K4Xfpm/mbBeG4AY1h4QIQfdsAWJ+CXcbhDVFyNWosjQ==", "referrer": "-", "version": "1.1", "user_agent": "com.apple.trustd/2.0", "origin": "-", "request_body_len": 0, "response_body_len": 471, "status_code": 200, "status_msg": "OK", "info_code": null, "info_msg": "-", "tags": [], "username": "-", "password": "-", "proxied": null, "orig_fuids": null, "orig_filenames": null, "orig_mime_types": null, "resp_fuids": ["FPtlyEAhcf8orBPu7"], "resp_filenames": null, "resp_mime_types": ["application/ocsp-response"]}
    {"ts": 1581245651.379048, "uid": "CuvUnl4HyhQbCs4tXe", "id.orig_h": "192.168.2.108", "id.orig_p": 56483, "id.resp_h": "23.59.247.10", "id.resp_p": 80, "trans_depth": 1, "method": "GET", "host": "isrg.trustid.ocsp.identrust.com", "uri": "/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFG/0aE1DEtJIYoGcwCs9Rywdii+mBBTEp7Gkeyxx+tvhS5B1/8QVYIWJEAIQCgFBQgAAAVOFc2oLheynCA==", "referrer": "-", "version": "1.1", "user_agent": "com.apple.trustd/2.0", "origin": "-", "request_body_len": 0, "response_body_len": 1398, "status_code": 200, "status_msg": "OK", "info_code": null, "info_msg": "-", "tags": [], "username": "-", "password": "-", "proxied": null, "orig_fuids": null, "orig_filenames": null, "orig_mime_types": null, "resp_fuids": ["FRfFoq3hSZkdCNDf9l"], "resp_filenames": null, "resp_mime_types": ["application/ocsp-response"]}
    {"ts": 1581245654.396334, "uid": "CWo4pd1z97XLB2o0h2", "id.orig_h": "192.168.2.108", "id.orig_p": 56486, "id.resp_h": "23.59.247.122", "id.resp_p": 80, "trans_depth": 1, "method": "GET", "host": "isrg.trustid.ocsp.identrust.com", "uri": "/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFG/0aE1DEtJIYoGcwCs9Rywdii+mBBTEp7Gkeyxx+tvhS5B1/8QVYIWJEAIQCgFBQgAAAVOFc2oLheynCA==", "referrer": "-", "version": "1.1", "user_agent": "com.apple.trustd/2.0", "origin": "-", "request_body_len": 0, "response_body_len": 1398, "status_code": 200, "status_msg": "OK", "info_code": null, "info_msg": "-", "tags": [], "username": "-", "password": "-", "proxied": null, "orig_fuids": null, "orig_filenames": null, "orig_mime_types": null, "resp_fuids": ["FvQehf1pRsGmwDUzJe"], "resp_filenames": null, "resp_mime_types": ["application/ocsp-response"]}
    {"ts": 1581245692.72884, "uid": "CxFQzh2ePtsnQhFNX3", "id.orig_h": "192.168.2.108", "id.orig_p": 56527, "id.resp_h": "23.59.247.10", "id.resp_p": 80, "trans_depth": 1, "method": "GET", "host": "isrg.trustid.ocsp.identrust.com", "uri": "/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFG/0aE1DEtJIYoGcwCs9Rywdii+mBBTEp7Gkeyxx+tvhS5B1/8QVYIWJEAIQCgFBQgAAAVOFc2oLheynCA==", "referrer": "-", "version": "1.1", "user_agent": "com.apple.trustd/2.0", "origin": "-", "request_body_len": 0, "response_body_len": 1398, "status_code": 200, "status_msg": "OK", "info_code": null, "info_msg": "-", "tags": [], "username": "-", "password": "-", "proxied": null, "orig_fuids": null, "orig_filenames": null, "orig_mime_types": null, "resp_fuids": ["FIeFj8WWNyhA1psGg"], "resp_filenames": null, "resp_mime_types": ["application/ocsp-response"]}
    {"ts": 1581245701.693971, "uid": "CPZSNk1Y6kDvAN0KZ8", "id.orig_h": "192.168.2.108", "id.orig_p": 56534, "id.resp_h": "23.59.247.122", "id.resp_p": 80, "trans_depth": 1, "method": "GET", "host": "isrg.trustid.ocsp.identrust.com", "uri": "/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFG/0aE1DEtJIYoGcwCs9Rywdii+mBBTEp7Gkeyxx+tvhS5B1/8QVYIWJEAIQCgFBQgAAAVOFc2oLheynCA==", "referrer": "-", "version": "1.1", "user_agent": "com.apple.trustd/2.0", "origin": "-", "request_body_len": 0, "response_body_len": 1398, "status_code": 200, "status_msg": "OK", "info_code": null, "info_msg": "-", "tags": [], "username": "-", "password": "-", "proxied": null, "orig_fuids": null, "orig_filenames": null, "orig_mime_types": null, "resp_fuids": ["F0fGHe4RPuNBhYWNv6"], "resp_filenames": null, "resp_mime_types": ["application/ocsp-response"]}
    {"ts": 1581245707.848088, "uid": "Cnab6CHFOprdppKi5", "id.orig_h": "192.168.2.108", "id.orig_p": 56542, "id.resp_h": "23.59.247.122", "id.resp_p": 80, "trans_depth": 1, "method": "GET", "host": "isrg.trustid.ocsp.identrust.com", "uri": "/MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFG/0aE1DEtJIYoGcwCs9Rywdii+mBBTEp7Gkeyxx+tvhS5B1/8QVYIWJEAIQCgFBQgAAAVOFc2oLheynCA==", "referrer": "-", "version": "1.1", "user_agent": "com.apple.trustd/2.0", "origin": "-", "request_body_len": 0, "response_body_len": 1398, "status_code": 200, "status_msg": "OK", "info_code": null, "info_msg": "-", "tags": [], "username": "-", "password": "-", "proxied": null, "orig_fuids": null, "orig_filenames": null, "orig_mime_types": null, "resp_fuids": ["FgDBep1h7EPHC8qQB6"], "resp_filenames": null, "resp_mime_types": ["application/ocsp-response"]}
    {"ts": 1581245952.784242, "uid": "CPNd6t3ofePpdNjErl", "id.orig_h": "192.168.2.108", "id.orig_p": 56821, "id.resp_h": "176.31.225.118", "id.resp_p": 80, "trans_depth": 1, "method": "GET", "host": "tracker.trackerfix.com", "uri": "/announce?info_hash=y\\x82es\"\\x1dV\\xde|m\\xbe\"\\xe5\\xef\\xbe\\x04\\xb3\\x1fW\\xfc&peer_id=-qB4210-0ZOn5Ifyl*WF&port=63108&uploaded=0&downloaded=0&left=3225455594&corrupt=0&key=6B23B036&event=started&numwant=200&compact=1&no_peer_id=1&supportcrypto=1&redundant=0", "referrer": "-", "version": "1.1", "user_agent": "-", "origin": "-", "request_body_len": 0, "response_body_len": 0, "status_code": 307, "status_msg": "Temporary Redirect", "info_code": null, "info_msg": "-", "tags": [], "username": "-", "password": "-", "proxied": null, "orig_fuids": null, "orig_filenames": null, "orig_mime_types": null, "resp_fuids": null, "resp_filenames": null, "resp_mime_types": null}
    {"ts": 1581245960.123295, "uid": "CfAkwf2CFI13b24gqf", "id.orig_h": "192.168.2.108", "id.orig_p": 56889, "id.resp_h": "176.31.225.118", "id.resp_p": 80, "trans_depth": 1, "method": "GET", "host": "tracker.trackerfix.com", "uri": "/announce?info_hash=!u7\\xdad\\x94x\\xecS\\x80\\x89\\x04\\x9c\\x13#\\x84M\\x1b\\xcd\\x1a&peer_id=-qB4210-i36iloGe*QT9&port=63108&uploaded=0&downloaded=0&left=1637966572&corrupt=0&key=ECE6637E&event=started&numwant=200&compact=1&no_peer_id=1&supportcrypto=1&redundant=0", "referrer": "-", "version": "1.1", "user_agent": "-", "origin": "-", "request_body_len": 0, "response_body_len": 0, "status_code": 307, "status_msg": "Temporary Redirect", "info_code": null, "info_msg": "-", "tags": [], "username": "-", "password": "-", "proxied": null, "orig_fuids": null, "orig_filenames": null, "orig_mime_types": null, "resp_fuids": null, "resp_filenames": null, "resp_mime_types": null}

How to Load/Parse a Log File?
-----------------------------

To load (parse) a log file generically, i.e. when you don't know what format
the log file is, you can simple call the ``~zlogging.loader.parse``,
``zlogging.loader.loads`` functions::

    # to parse log at filename
    >>> parse('path/to/log')
    # to load log from a file object
    >>> with open('path/to/log', 'rb') as file:
    ...     load(file)
    # to load log from a string
    >>> with open('/path/to/log', 'rb') as file:
    ...     loads(file.read())

.. note::

    ``zlogging.loader.load``, the file object must be opened
        in binary mode.

    ``zlogging.loader.loads``, if the ``data`` suplied is an
        encoded string (``str``), the function will first try to decode it as a
        bytestring (``bytes``) with ``'ascii'`` encoding.

If you do know the format, you may call the specified functions for each
``zlogging.loader.parse_ascii`` and ``zlogging.loader.parse_json``, etc.

If you would like to customise your own parser, just subclass
``zlogging.loader.BaseParser`` and implement your own ideas.

How to Dump/Write a Log File?
-----------------------------

Before dumping (writing) a log file, you need to create a log **data model**
first. Just like in the Bro/Zeek script language, when customise logging, you
need to notify the logging framework with a new log stream. Here, in
``ZLogging``, we introduced **data model** for the same purpose.

A **data model** is a subclass of ``zlogging.model.Model`` with fields
and data types declared. A typical **data model** can be as following::

    class MyLog(Model):
        field_one = StringType()
        field_two = SetType(element_type=PortType)

where ``field_one`` is ``string`` type, i.e. ``zlogging.types.StringType``;
and ``field_two`` is ``set[port]`` types, i.e. ``zlogging.types.SetType``
of ``zlogging.types.PortType``.

Or you may use type annotations as `PEP 484`_ introduced when declaring **data models**.
All available type hints can be found in ``zlogging.typing``::

    class MyLog(Model):
        field_one: zeek_string
        field_two: zeek_set[zeek_port]

After declaration of your **data model**, you can know dump (write) your log
file with the corresponding functions.

If you would like to customise your own writer, just subclass
``zlogging.loader.BaseWriter`` and implement your own ideas.

.. _PEP 484:
    https://www.python.org/dev/peps/pep-0484/

.. [1] https://blog.zeek.org/2018/10/renaming-bro-project_11.html
