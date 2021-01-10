Typing Annotations
==================

.. .. automodule:: zlogging.typing
..    :members:
..    :undoc-members:
..    :show-inheritance:

Zeek Data Types
---------------

.. autodata:: zlogging.typing.zeek_addr
.. autodata:: zlogging.typing.zeek_bool
.. autodata:: zlogging.typing.zeek_count
.. autodata:: zlogging.typing.zeek_double
.. autodata:: zlogging.typing.zeek_enum
.. autodata:: zlogging.typing.zeek_interval
.. autodata:: zlogging.typing.zeek_int
.. autodata:: zlogging.typing.zeek_port

.. data:: zlogging.typing.zeek_record
    :value: ~record

    Zeek ``record`` data type.

    .. note::

        As a *variadic* data type, it supports the typing proxy as :obj:`TypedDict`,
        introduced in `PEP 589`_::

            class MyLog(zeek_record):
                field_one: zeek_int
                field_two: zeek_set[zeek_port]

        which is the same **at runtime** as following::

            RecordType(field_one=IntType,
                       field_two=SetType(element_type=PortType))

        .. _PEP 589:
            https://www.python.org/dev/peps/pep-0589

    .. seealso::

        See :func:`~zlogging._aux.expand_typing` for more information about the
        processing of typing proxy.

.. data:: zlogging.typing.zeek_set
    :value: ~set

    Zeek ``set`` data type.

    .. note::

        As a *generic* data type, the class supports the typing proxy as introduced
        `PEP 484`_::

            class MyLog(zeek_record):
                field_one: zeek_set[zeek_str]

        which is the same **at runtime** as following::

            class MyLog(zeek_record):
                field_one = SetType(element_type=StringType())

        .. _PEP 484:
            https://www.python.org/dev/peps/pep-0484/

.. autodata:: zlogging.typing.zeek_string
.. autodata:: zlogging.typing.zeek_subnet
.. autodata:: zlogging.typing.zeek_time

.. data:: zlogging.typing.zeek_vector
    :value: ~vector

    Zeek ``vector`` data type.

    .. note::

        As a *generic* data type, the class supports the typing proxy as introduced
        `PEP 484`_::

            class MyLog(zeek_record):
                field_one: zeek_vector[zeek_str]

        which is the same **at runtime** as following::

            class MyLog(zeek_record):
                field_one = VectorType(element_type=StringType())

        .. _PEP 484:
            https://www.python.org/dev/peps/pep-0484/

Bro Data Types
--------------

Use of ``bro`` is deprecated. Please use ``zeek`` instead.

.. autodata:: zlogging.typing.bro_addr
.. autodata:: zlogging.typing.bro_bool
.. autodata:: zlogging.typing.bro_count
.. autodata:: zlogging.typing.bro_double
.. autodata:: zlogging.typing.bro_enum
.. autodata:: zlogging.typing.bro_interval
.. autodata:: zlogging.typing.bro_int
.. autodata:: zlogging.typing.bro_port

.. data:: zlogging.typing.bro_record
    :value: ~bro_record

    Bro ``record`` data type.

    .. seealso::

        See :attr:`~zlogging.typing.zeek_record` for more information.

.. data:: zlogging.typing.bro_set
    :value: ~bro_set

    Bro ``set`` data type.

    .. seealso::

        See :attr:`~zlogging.typing.zeek_set` for more information.

.. autodata:: zlogging.typing.bro_string
.. autodata:: zlogging.typing.bro_subnet
.. autodata:: zlogging.typing.bro_time

.. data:: zlogging.typing.bro_vector
    :value: ~bro_vector

    Bro ``vector`` data type.

    .. seealso::

        See :attr:`~zlogging.typing.zeek_vector` for more information.
