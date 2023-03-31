.. image:: https://ci.appveyor.com/api/projects/status/gidnb9ulj3rje5s2?svg=true
    :target: https://ci.appveyor.com/project/plusvic/yara-python

yara-python
===========

With this library you can use `YARA <https://github.com/VirusTotal/yara>`_ from
your Python programs. It covers all YARA's features, from compiling, saving
and loading rules to scanning files, strings and processes.

Here it goes a little example:

.. code-block:: python

    >>> import yara
    >>> rule = yara.compile(source='rule foo: bar {strings: $a = "lmn" condition: $a}')
    >>> matches = rule.match(data='abcdefgjiklmnoprstuvwxyz')
    >>> print(matches)
    [foo]
    >>> print(matches[0].rule)
    foo
    >>> print(matches[0].tags)
    ['bar']
    >>> print(matches[0].strings)
    [$a]
    >>> print(matches[0].strings[0].identifier)
    $a
    >>> print(matches[0].strings[0].instances)
    [lmn]
    >>> print(matches[0].strings[0].instances[0].offset)
    10
    >>> print(matches[0].strings[0].instances[0].matched_length)
    3


Installation
------------

The easiest way of installing YARA is by using ``pip``:

.. code-block:: bash

  $ pip install yara-python

But you can also get the source from GitHub and compile it yourself:

.. code-block:: bash

  $ git clone --recursive https://github.com/VirusTotal/yara-python
  $ cd yara-python
  $ python setup.py build
  $ sudo python setup.py install

Notice the ``--recursive`` option used with ``git``. This is important because
we need to download the ``yara`` subproject containing the source code for
``libyara`` (the core YARA library). It's also important to note that the two
methods above link ``libyara`` statically into yara-python. If you want to link
dynamically against a shared ``libyara`` library use:

.. code-block:: bash

  $ python setup.py build --dynamic-linking

For this option to work you must build and install
`YARA <https://github.com/VirusTotal/yara>`_ separately before installing
``yara-python``.


Documentation
-------------

Find more information about how to use yara-python at
https://yara.readthedocs.org/en/latest/yarapython.html.
