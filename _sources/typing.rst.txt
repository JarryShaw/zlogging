Typing Annotations
==================

Zeek Data Types
---------------

Boolean
~~~~~~~

.. data:: zlogging.typing.zeek_bool
   :type: BoolType

   Zeek ``bool`` data type.

Numeric Types
~~~~~~~~~~~~~

.. data:: zlogging.typing.zeek_count
   :type: CountType

   Zeek ``count`` data type.

.. data:: zlogging.typing.zeek_double
   :type: DoubleType

   Zeek ``count`` data type.

.. data:: zlogging.typing.zeek_int
   :type: IntType

   Zeek ``int`` data type.

Time Types
~~~~~~~~~~

.. data:: zlogging.typing.zeek_time
   :type: TimeType

   Zeek ``time`` data type.

.. data:: zlogging.typing.zeek_interval
   :type: IntervalType

   Zeek ``interval`` data type.

String
~~~~~~

.. data:: zlogging.typing.zeek_string
   :type: StringType

   Zeek ``string`` data type.

Network Types
~~~~~~~~~~~~~

.. data:: zlogging.typing.zeek_port
   :type: PortType

   Zeek ``port`` data type.

.. data:: zlogging.typing.zeek_addr
   :type: AddrType

   Zeek ``addr`` data type.

.. data:: zlogging.typing.zeek_subnet
   :type: SubnetType

   Zeek ``subnet`` data type.

Enumeration
~~~~~~~~~~~

.. data:: zlogging.typing.zeek_enum
   :type: EnumType

   Zeek ``enum`` data type.

Container Types
~~~~~~~~~~~~~~~

.. autoclass:: zlogging.typing.zeek_set
   :no-members:
   :show-inheritance:

   :param empty_field: Placeholder for empty field.
   :param unset_field: Placeholder for unset field.
   :param set_separator: Separator for ``set``/``vector`` fields.
   :param element_type: Data type of container's elements.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: zlogging.typing.zeek_vector
   :no-members:
   :show-inheritance:

   :param empty_field: Placeholder for empty field.
   :param unset_field: Placeholder for unset field.
   :param set_separator: Separator for ``set``/``vector`` fields.
   :param element_type: Data type of container's elements.
   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: zlogging.typing.zeek_record
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

Bro Data Types
--------------

.. warning::

   Use of ``bro`` is deprecated. Please use ``zeek`` instead.

Boolean
~~~~~~~

.. data:: zlogging.typing.bro_bool
   :type: BoolType

   Bro ``bool`` data type.

Numeric Types
~~~~~~~~~~~~~

.. data:: zlogging.typing.bro_count
   :type: CountType

   Bro ``count`` data type.

.. data:: zlogging.typing.bro_double
   :type: CountType

   Bro ``count`` data type.

.. data:: zlogging.typing.bro_int
   :type: IntType

   Bro ``int`` data type.

Time Types
~~~~~~~~~~

.. data:: zlogging.typing.bro_time
   :type: TimeType

   Bro ``time`` data type.

.. data:: zlogging.typing.bro_interval
   :type: IntervalType

   Bro ``interval`` data type.

String
~~~~~~

.. data:: zlogging.typing.bro_string
   :type: StringType

   Bro ``string`` data type.

Network Types
~~~~~~~~~~~~~

.. data:: zlogging.typing.bro_port
   :type: PortType

   Bro ``port`` data type.

.. data:: zlogging.typing.bro_addr
   :type: AddrType

   Bro ``addr`` data type.

.. data:: zlogging.typing.bro_subnet
   :type: SubnetType

   Bro ``subnet`` data type.

Enumeration
~~~~~~~~~~~

.. data:: zlogging.typing.bro_enum
   :type: EnumType

   Bro ``enum`` data type.

Container Types
~~~~~~~~~~~~~~~

.. autoclass:: zlogging.typing.bro_set
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: zlogging.typing.bro_vector
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: zlogging.typing.bro_record
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.
