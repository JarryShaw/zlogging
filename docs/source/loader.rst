Log Loaders
===========

.. module:: zlogging.loader

Functional Interfaces
---------------------

General APIs
~~~~~~~~~~~~

.. autofunction:: zlogging.loader.parse
.. autofunction:: zlogging.loader.loads
.. autofunction:: zlogging.loader.load

ASCII Format
~~~~~~~~~~~~

.. autofunction:: zlogging.loader.parse_ascii
.. autofunction:: zlogging.loader.loads_ascii
.. autofunction:: zlogging.loader.load_ascii

JSON Format
~~~~~~~~~~~

.. autofunction:: zlogging.loader.parse_json
.. autofunction:: zlogging.loader.loads_json
.. autofunction:: zlogging.loader.load_json

Predefined Loaders
------------------

.. autoclass:: zlogging.loader.ASCIIParser
   :members:
   :show-inheritance:

.. autoclass:: zlogging.loader.JSONParser
   :members:
   :show-inheritance:

Abstract Base Loader
--------------------

.. autoclass:: zlogging.loader.BaseParser
   :members:
   :show-inheritance:
