#
# Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from distutils.command.build import build
from setuptools import setup, Extension

import distutils.errors
import distutils.ccompiler
import distutils.sysconfig

import contextlib
import os
import sys
import tempfile
import shutil
import subprocess

@contextlib.contextmanager
def muted(*streams):
  """A context manager to redirect stdout and/or stderr to /dev/null.

  Examples:
    with muted(sys.stdout):
      ...

    with muted(sys.stderr):
      ...

    with muted(sys.stdout, sys.stderr):
      ...
  """
  devnull = open(os.devnull, 'w')
  try:
    old_streams = [os.dup(s.fileno()) for s in streams]
    for s in streams:
      os.dup2(devnull.fileno(), s.fileno())
    yield
  finally:
    for o,n in zip(old_streams, streams):
      os.dup2(o, n.fileno())
    devnull.close()


def has_function(function_name, libraries=None):
  compiler = distutils.ccompiler.new_compiler()
  with muted(sys.stdout, sys.stderr):
    result = compiler.has_function(
        function_name, libraries=libraries)
  if os.path.exists('a.out'):
    os.remove('a.out')
  return result


class BuildCommand(build):

  user_options = build.user_options + [
      ('static','s','build libyara statically into yara-python module'),
      ('enable-cuckoo', None,'enable "cuckoo" module (use with --static)'),
      ('enable-magic', None,'enable "magic" module (use with --static)'),
      ('enable-profiling', None,'enable profiling features')]

  boolean_options = build.boolean_options + [
      'static', 'enable-cuckoo', 'enable-magic', 'enable-profiling']

  def initialize_options(self):
    build.initialize_options(self)
    self.static = None
    self.enable_magic = None
    self.enable_cuckoo = None
    self.enable_profiling = None

  def finalize_options(self):
    build.finalize_options(self)
    if self.enable_magic and not self.static:
      raise distutils.errors.DistutilsOptionError(
          '--enable-magic must be used with --static')
    if self.enable_cuckoo and not self.static:
      raise distutils.errors.DistutilsOptionError(
          '--enable-cuckoo must be used with --static')

  def run(self):
    sources = ['./yara-python.c']
    exclusions = ['yara/libyara/modules/pe_utils.c']
    libraries = ['yara']
    include_dirs = []
    macros = []

    if has_function('memmem'):
      macros.append(('HAVE_MEMMEM', '1'))
    if has_function('strlcpy'):
      macros.append(('HAVE_STRLCPY', '1'))
    if has_function('strlcat'):
      macros.append(('HAVE_STRLCAT', '1'))

    if self.enable_profiling:
      macros.append(('PROFILING_ENABLED', '1'))

    if self.static:
      libraries = []
      include_dirs = ['yara/libyara/include', 'yara/libyara/', '.']

      if (has_function('MD5_Init', libraries=['crypto']) and 
          has_function('SHA256_Init', libraries=['crypto'])):
        macros.append(('HASH', '1'))
        libraries.append('crypto')
      else:
        exclusions.append('yara/libyara/modules/hash.c')

      if self.enable_magic:
        macros.append(('MAGIC', '1'))
      else:
        exclusions.append('yara/libyara/modules/magic.c')

      if self.enable_cuckoo:
        macros.append(('CUCKOO', '1'))
      else:
        exclusions.append('yara/libyara/modules/cuckoo.c')

      for directory, _, files in os.walk('yara/libyara/'):
        for x in files:
          x = os.path.join(directory, x)
          if x.endswith('.c') and x not in exclusions:
            sources.append(x)

    self.distribution.ext_modules = [Extension(
        name='yara',
        sources=sources,
        include_dirs=include_dirs,
        libraries=libraries,
        define_macros=macros,
        extra_compile_args=['-std=gnu99', '-Wno-deprecated-declarations'])]

    build.run(self)


setup(
    name='yara-python',
    version='3.4.1',
    author='Victor M. Alvarez',
    author_email='plusvic@gmail.com;vmalvarez@virustotal.com',
    url='https://github.com/plusvic/yara-python',
    zip_safe=False,
    cmdclass={'build': BuildCommand})
