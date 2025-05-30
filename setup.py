#
# Copyright (c) 2007-2022. The YARA Authors. All Rights Reserved.
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

from setuptools import setup, Command, Extension
from distutils.command.build import build
from distutils.command.build_ext import build_ext
from codecs import open

import distutils.errors
import distutils.ccompiler
import distutils.sysconfig

import contextlib
import os
import sys
import tempfile
import shutil
import subprocess

OPTIONS = [
   ('dynamic-linking', None, 'link dynamically against libyara'),
   ('enable-cuckoo', None, 'enable "cuckoo" module'),
   ('enable-magic', None, 'enable "magic" module'),
   ('enable-dex', None, 'enable "dex" module'),
   ('enable-macho', None, 'enable "macho" module'),
   ('enable-profiling', None, 'enable profiling features'),
   ('enable-openssl', None, 'enable features that depend on OpenSSL'),
]


BOOLEAN_OPTIONS = [
    'dynamic-linking',
    'enable-cuckoo',
    'enable-magic',
    'enable-dex',
    'enable-macho',
    'enable-profiling',
    'enable-openssl',
]


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


def has_function(function_name, includes=None, include_dirs=None, libraries=None, library_dirs=None):
  """Checks if a given functions exists in the current platform."""
  compiler = distutils.ccompiler.new_compiler()
  with muted(sys.stdout, sys.stderr):
      result = compiler.has_function(
          function_name,
          includes=includes,
          include_dirs=include_dirs,
          libraries=libraries,
          library_dirs=library_dirs)
  if os.path.exists('a.out'):
    os.remove('a.out')
  return result


def has_header(header_name):
  compiler = distutils.ccompiler.new_compiler()
  with muted(sys.stdout, sys.stderr):
    with tempfile.NamedTemporaryFile(mode='w', prefix=header_name, delete=False, suffix='.c') as f:
      f.write("""
#include <{}>

int main() {{ return 0; }}
      """.format(header_name))
      f.close()
      try:
        compiler.compile([f.name])
      except distutils.errors.CompileError:
        return False
  return True


class BuildCommand(build):

  user_options = build.user_options + OPTIONS
  boolean_options = build.boolean_options + BOOLEAN_OPTIONS

  def initialize_options(self):

    build.initialize_options(self)
    self.dynamic_linking = None
    self.enable_magic = None
    self.enable_cuckoo = None
    self.enable_dex = None
    self.enable_macho = None
    self.enable_profiling = None
    self.enable_openssl = None

  def finalize_options(self):

    build.finalize_options(self)



class BuildExtCommand(build_ext):

  user_options = build_ext.user_options + OPTIONS
  boolean_options = build_ext.boolean_options + BOOLEAN_OPTIONS

  def initialize_options(self):

    build_ext.initialize_options(self)
    self.dynamic_linking = None
    self.enable_magic = None
    self.enable_cuckoo = None
    self.enable_dex = None
    self.enable_macho = None
    self.enable_profiling = None
    self.enable_openssl = None

  def finalize_options(self):

    build_ext.finalize_options(self)

    # If the build_ext command was invoked by the build command, take the
    # values for these options from the build command.

    self.set_undefined_options('build',
        ('dynamic_linking', 'dynamic_linking'),
        ('enable_magic', 'enable_magic'),
        ('enable_cuckoo', 'enable_cuckoo'),
        ('enable_dex', 'enable_dex'),
        ('enable_macho', 'enable_macho'),
        ('enable_profiling', 'enable_profiling'),
        ('enable_openssl', 'enable_openssl'))

    if self.enable_magic and self.dynamic_linking:
      raise distutils.errors.DistutilsOptionError(
          '--enable-magic can''t be used with --dynamic-linking')
    if self.enable_cuckoo and self.dynamic_linking:
      raise distutils.errors.DistutilsOptionError(
          '--enable-cuckoo can''t be used with --dynamic-linking')
    if self.enable_dex and self.dynamic_linking:
      raise distutils.errors.DistutilsOptionError(
          '--enable-dex can''t be used with --dynamic-linking')
    if self.enable_macho and self.dynamic_linking:
      raise distutils.errors.DistutilsOptionError(
          '--enable-macho can''t be used with --dynamic-linking')
    if self.enable_openssl and self.dynamic_linking:
      raise distutils.errors.DistutilsOptionError(
          '--enable-openssl can''t be used with --dynamic-linking')


  def run(self):
    """Execute the build command."""

    module = self.distribution.ext_modules[0]
    base_dir = os.path.dirname(__file__)

    if base_dir:
      os.chdir(base_dir)

    exclusions = []

    for define in self.define or []:
      module.define_macros.append(define)

    for library in self.libraries or []:
      module.libraries.append(library)

    building_for_windows = self.plat_name in ('win32','win-amd64')
    building_for_osx = 'macosx' in self.plat_name
    building_for_linux = 'linux' in self.plat_name
    building_for_freebsd = 'freebsd' in self.plat_name
    building_for_openbsd = 'openbsd' in self.plat_name # need testing

    if building_for_windows:
      arch = 'x86' if self.plat_name == 'win32' else 'x64'
      openssl_include_dirs = [
        os.path.join(base_dir, 'yara\\windows\\vs2015\\packages\\YARA.OpenSSL.{}.1.1.1\\include'.format(arch)),
        os.path.join(base_dir, 'yara\\windows\\vs2017\\packages\\YARA.OpenSSL.{}.1.1.1\\include'.format(arch))
      ]
      openssl_library_dirs = [
        os.path.join(base_dir, 'yara\\windows\\vs2015\\packages\\YARA.OpenSSL.{}.1.1.1\\lib'.format(arch)),
        os.path.join(base_dir, 'yara\\windows\\vs2017\\packages\\YARA.OpenSSL.{}.1.1.1\\lib'.format(arch))
      ]
      openssl_libraries = ['libcrypto']
    else:
      openssl_include_dirs = []
      openssl_library_dirs = []
      openssl_libraries = ['crypto']

    if building_for_linux:
      module.define_macros.append(('_GNU_SOURCE', '1'))
      module.define_macros.append(('USE_LINUX_PROC', '1'))
      module.extra_compile_args.append('-std=c99')
    elif building_for_windows:
      module.define_macros.append(('USE_WINDOWS_PROC', '1'))
      module.define_macros.append(('_CRT_SECURE_NO_WARNINGS', '1'))
      module.libraries.append('kernel32')
      module.libraries.append('advapi32')
      module.libraries.append('user32')
      module.libraries.append('crypt32')
      module.libraries.append('ws2_32')
    elif building_for_osx:
      module.define_macros.append(('_GNU_SOURCE', '1'))
      module.define_macros.append(('USE_MACH_PROC', '1'))
      module.extra_compile_args.append('-std=c99')
      module.include_dirs.append('/usr/local/opt/openssl/include')
      module.include_dirs.append('/opt/local/include')
      module.library_dirs.append('/opt/local/lib')
      module.include_dirs.append('/usr/local/include')
      module.library_dirs.append('/usr/local/lib')
      module.library_dirs.append('/usr/local/opt/openssl/lib')
      module.include_dirs.append('/opt/homebrew/include')
      module.library_dirs.append('/opt/homebrew/opt/openssl/lib')
    elif building_for_freebsd:
      module.define_macros.append(('_GNU_SOURCE', '1'))
      module.define_macros.append(('USE_FREEBSD_PROC', '1'))
      module.include_dirs.append('/opt/local/include')
      module.library_dirs.append('/opt/local/lib')
      module.include_dirs.append('/usr/local/include')
      module.library_dirs.append('/usr/local/lib')
    elif building_for_openbsd:
      module.define_macros.append(('_GNU_SOURCE', '1'))
      module.define_macros.append(('USE_OPENBSD_PROC', '1'))
      module.extra_compile_args.append('-std=c99')
      module.include_dirs.append('/opt/local/include')
      module.library_dirs.append('/opt/local/lib')
      module.include_dirs.append('/usr/local/include')
      module.library_dirs.append('/usr/local/lib')
    else:
      module.define_macros.append(('_GNU_SOURCE', '1'))
      module.define_macros.append(('USE_NO_PROC', '1'))
      module.extra_compile_args.append('-std=c99')

    if has_header('stdbool.h'):
      module.define_macros.append(('HAVE_STDBOOL_H', '1'))

    if has_function('memmem'):
      module.define_macros.append(('HAVE_MEMMEM', '1'))
    if has_function('strlcpy'):
      module.define_macros.append(('HAVE_STRLCPY', '1'))
    if has_function('strlcat'):
      module.define_macros.append(('HAVE_STRLCAT', '1'))

    if self.enable_profiling:
      module.define_macros.append(('YR_PROFILING_ENABLED', '1'))

    if self.dynamic_linking:
      module.libraries.append('yara')
    else:
      # Is OpenSSL available?
      if (has_function('OpenSSL_add_all_algorithms',
                       includes=['openssl/evp.h'],
                       include_dirs=module.include_dirs + openssl_include_dirs,
                       libraries=module.libraries + openssl_libraries,
                       library_dirs=module.library_dirs + openssl_library_dirs)
          # In case OpenSSL is being linked statically
          or has_function('OpenSSL_add_all_algorithms',
                       includes=['openssl/evp.h'],
                       include_dirs=module.include_dirs + openssl_include_dirs,
                       libraries=module.libraries + openssl_libraries + ['dl', 'pthread', 'z'],
                       library_dirs=module.library_dirs + openssl_library_dirs)
          or self.enable_openssl):
        module.define_macros.append(('HASH_MODULE', '1'))
        module.define_macros.append(('HAVE_LIBCRYPTO', '1'))
        module.libraries.extend(openssl_libraries)
        module.include_dirs.extend(openssl_include_dirs)
        module.library_dirs.extend(openssl_library_dirs)
      elif building_for_windows:
        # OpenSSL is not available, but in Windows we can rely on Wincrypt for
        # hashing functions.
        module.define_macros.append(('HASH_MODULE', '1'))
        module.define_macros.append(('HAVE_WINCRYPT_H', '1'))
        # The authenticode parser depends on OpenSSL and must be excluded.
        exclusions.append('yara/libyara/modules/pe/authenticode-parser')
      else:
        # Without OpenSSL there's no hash module nor authenticode parser.
        exclusions.append('yara/libyara/modules/hash/hash.c')
        exclusions.append('yara/libyara/modules/pe/authenticode-parser')

      if self.enable_magic:
        module.define_macros.append(('MAGIC_MODULE', '1'))
        module.libraries.append('magic')
      else:
        exclusions.append('yara/libyara/modules/magic/magic.c')

      if self.enable_cuckoo:
        module.define_macros.append(('CUCKOO_MODULE', '1'))
        module.libraries.append('jansson')
      else:
        exclusions.append('yara/libyara/modules/cuckoo/cuckoo.c')

      if self.enable_dex:
        module.define_macros.append(('DEX_MODULE', '1'))
      else:
        exclusions.append('yara/libyara/modules/dex/dex.c')

      if self.enable_macho:
        module.define_macros.append(('MACHO_MODULE', '1'))
      else:
        exclusions.append('yara/libyara/modules/macho/macho.c')

      # exclude pb_tests module
      exclusions.append('yara/libyara/modules/pb_tests/pb_tests.c')
      exclusions.append('yara/libyara/modules/pb_tests/pb_tests.pb-c.c')

      # Always turn on the DOTNET module.
      module.define_macros.append(('DOTNET_MODULE', '1'))

      exclusions = [os.path.normpath(x) for x in exclusions]

      for directory, _, files in os.walk('yara/libyara/'):
        for f in files:
          f = os.path.normpath(os.path.join(directory, f))
          # Ignore any file that is not a .c file
          if not f.endswith('.c'):
            continue
          # Ignore files that are listed in the exclusion list.
          if any(map(lambda e: f.startswith(e), exclusions)):
            continue
          module.sources.append(f)

    build_ext.run(self)


class UpdateCommand(Command):
  """Update libyara source.

  This is normally only run by packagers to make a new release.
  """
  user_options = []

  def initialize_options(self):
    pass

  def finalize_options(self):
    pass

  def run(self):
    subprocess.check_call(['git', 'stash'], cwd='yara')

    subprocess.check_call(['git', 'submodule', 'init'])
    subprocess.check_call(['git', 'submodule', 'update'])

    subprocess.check_call(['git', 'reset', '--hard'], cwd='yara')
    subprocess.check_call(['git', 'clean', '-x', '-f', '-d'], cwd='yara')

    subprocess.check_call(['git', 'checkout', 'master'], cwd='yara')
    subprocess.check_call(['git', 'pull'], cwd='yara')
    subprocess.check_call(['git', 'fetch', '--tags'], cwd='yara')

    tag_name = 'tags/v%s' % self.distribution.metadata.version
    subprocess.check_call(['git', 'checkout', tag_name], cwd='yara')

    subprocess.check_call(['./bootstrap.sh'], cwd='yara')
    subprocess.check_call(['./configure'], cwd='yara')


with open('README.rst', 'r', 'utf-8') as f:
  readme = f.read()

setup(
    name='yara-python',
    version='4.5.4',
    description='Python interface for YARA',
    long_description=readme,
    long_description_content_type='text/markdown',
    license='Apache 2.0',
    author='Victor M. Alvarez',
    author_email='plusvic@gmail.com, vmalvarez@virustotal.com',
    url='https://github.com/VirusTotal/yara-python',
    classifiers=[
        'Programming Language :: Python',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Development Status :: 5 - Production/Stable',
    ],
    zip_safe=False,
    cmdclass={
        'build': BuildCommand,
        'build_ext': BuildExtCommand,
        'update': UpdateCommand},
    ext_modules=[Extension(
        name='yara',
        include_dirs=['yara/libyara/include', 'yara/libyara/', '.'],
        define_macros=[('BUCKETS_128', 1), ('CHECKSUM_1B', 1)],
        sources=['yara-python.c'])])
