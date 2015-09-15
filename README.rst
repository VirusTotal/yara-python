yara-python
===========

This is library for using `YARA <https://github.com/plusvic/yara>`_ from Python.
You can use it to compile, save and load YARA rules, and to scan files or
data strings.

Here it goes a little example:

.. code-block:: bash

	>>> import yara
    >>> rule = yara.compile(source='rule foo {strings: $a = "lmn" condition: $a}')
    >>> matches = rule.match(data='abcdefgjiklmnoprstuvwxyz')
    >>> for m in matches:
    ...     print m.rule
    ...     print m.strings
    ...
    foo
    [(10L, '$a', 'lmn')]


Installation
------------

Before installing yara-python you'll need to install YARA, except if you plan
to link YARA statically into yara-python. If you don't have a specific reason
for using the static linking method, just install YARA as described in it
`documentation <http://yara.readthedocs.org/en/latest/gettingstarted.html#compiling-and-installing-yara`_
and then:

.. code-block:: bash

	$ pip install yara-python

Documentation
-------------

You can find more information about how to use yara-python at
http://yara.readthedocs.org/en/latest/yarapython.html.

