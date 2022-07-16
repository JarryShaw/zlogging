Log Dumpers
===========

.. module:: zlogging.dumper

Functional Interfaces
---------------------

General APIs
~~~~~~~~~~~~

.. autofunction:: zlogging.dumper.write
.. autofunction:: zlogging.dumper.dumps
.. autofunction:: zlogging.dumper.dump

ASCII Format
~~~~~~~~~~~~

.. autofunction:: zlogging.dumper.write_ascii
.. autofunction:: zlogging.dumper.dumps_ascii
.. autofunction:: zlogging.dumper.dump_ascii

JSON Format
~~~~~~~~~~~

.. autofunction:: zlogging.dumper.write_json
.. autofunction:: zlogging.dumper.dumps_json
.. autofunction:: zlogging.dumper.dump_json

Predefined Dumpers
------------------

.. autoclass:: zlogging.dumper.ASCIIWriter
   :members:
   :show-inheritance:

.. autoclass:: zlogging.dumper.JSONWriter
   :members:
   :show-inheritance:

Abstract Base Dumper
--------------------

.. autoclass:: zlogging.dumper.BaseWriter
   :members:
   :show-inheritance:
