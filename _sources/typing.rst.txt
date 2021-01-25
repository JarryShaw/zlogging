Typing Annotations
==================

.. .. automodule:: zlogging.typing
..    :members:
..    :undoc-members:
..    :show-inheritance:

Zeek Data Types
---------------

Simple Types
~~~~~~~~~~~~

.. autodata:: zlogging.typing.zeek_addr
.. autodata:: zlogging.typing.zeek_bool
.. autodata:: zlogging.typing.zeek_count
.. autodata:: zlogging.typing.zeek_double
.. autodata:: zlogging.typing.zeek_enum
.. autodata:: zlogging.typing.zeek_interval
.. autodata:: zlogging.typing.zeek_int
.. autodata:: zlogging.typing.zeek_port
.. autodata:: zlogging.typing.zeek_string
.. autodata:: zlogging.typing.zeek_subnet
.. autodata:: zlogging.typing.zeek_time

Generic Types
~~~~~~~~~~~~~

.. autoclass:: zlogging.typing.zeek_set
.. autoclass:: zlogging.typing.zeek_vector

Variadic Types
~~~~~~~~~~~~~~

.. autoclass:: zlogging.typing.zeek_record

Bro Data Types
--------------

.. warning::

   Use of ``bro`` is deprecated. Please use ``zeek`` instead.

Simple Types
~~~~~~~~~~~~

.. autodata:: zlogging.typing.bro_addr
.. autodata:: zlogging.typing.bro_bool
.. autodata:: zlogging.typing.bro_count
.. autodata:: zlogging.typing.bro_double
.. autodata:: zlogging.typing.bro_enum
.. autodata:: zlogging.typing.bro_interval
.. autodata:: zlogging.typing.bro_int
.. autodata:: zlogging.typing.bro_port
.. autodata:: zlogging.typing.bro_string
.. autodata:: zlogging.typing.bro_subnet
.. autodata:: zlogging.typing.bro_time

Generic Types
~~~~~~~~~~~~~

.. autoclass:: zlogging.typing.bro_set
.. autoclass:: zlogging.typing.bro_vector

Variadic Types
~~~~~~~~~~~~~~

.. autoclass:: zlogging.typing.bro_record
