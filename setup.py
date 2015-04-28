#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup, Extension
from distutils.util import execute, newer
from distutils.spawn import spawn

#
# hack to support linking when running
#  python setup.py sdist
#

import os
del os.link

if newer('./src/getdate.y', './src/getdate.c'):
    execute(spawn, (['bison', '-y', '-o', './src/getdate.c', './src/getdate.y'],))

setup(name='python-kadmin',
      version='0.1.1',
      description='Python module for kerberos admin (kadm5)',
      url='https://github.com/russjancewicz/python-kadmin',
      download_url='https://github.com/russjancewicz/python-kadmin/tarball/v0.1.1',
      author='Russell Jancewicz',
      author_email='russell.jancewicz@gmail.com',
      license='MIT',
      ext_modules=[
          Extension(
              "kadmin",
              libraries=["krb5", "kadm5clnt", "kdb5"],
              include_dirs=["/usr/include/", "/usr/include/et/"],
              sources=[
                  "src/kadmin.c",
                  "src/PyKAdminErrors.c",
                  "src/PyKAdminObject.c",
                  "src/PyKAdminIterator.c",
                  "src/PyKAdminPrincipalObject.c",
                  "src/PyKAdminPolicyObject.c",
                  "src/PyKAdminCommon.c",
                  "src/PyKAdminXDR.c",
                  "src/getdate.c"
                  ],
              #extra_compile_args=["-O0"]
              )
          ],
      classifiers=[
          "Development Status :: 4 - Beta",
          "Environment :: Console",
          "Intended Audience :: System Administrators",
          "Intended Audience :: Developers",
          "Operating System :: POSIX",
          "Programming Language :: C",
          "Programming Language :: Python",
          "Programming Language :: YACC",
          "License :: OSI Approved :: MIT License",
          "Topic :: Software Development :: Libraries :: Python Modules",
          "Topic :: System :: Systems Administration :: Authentication/Directory",
          ]
      )

setup(name='python-kadmin-local',
      version='0.1.1',
      description='Python module for kerberos admin (kadm5) via root local interface',
      url='https://github.com/russjancewicz/python-kadmin',
      download_url='https://github.com/russjancewicz/python-kadmin/tarball/v0.1.1',
      author='Russell Jancewicz',
      author_email='russell.jancewicz@gmail.com',
      license='MIT',
      ext_modules=[
          Extension(
              "kadmin_local",
              libraries=["krb5", "kadm5srv", "kdb5"],
              include_dirs=["/usr/include/", "/usr/include/et/"],
              sources=[
                  "src/kadmin.c",
                  "src/PyKAdminErrors.c",
                  "src/PyKAdminObject.c",
                  "src/PyKAdminIterator.c",
                  "src/PyKAdminPrincipalObject.c",
                  "src/PyKAdminPolicyObject.c",
                  "src/PyKAdminCommon.c",
                  "src/PyKAdminXDR.c",
                  "src/getdate.c"
                  ],
              define_macros=[('KADMIN_LOCAL', '')]
              )
          ],
      classifiers=[
          "Development Status :: 4 - Beta",
          "Environment :: Console",
          "Intended Audience :: System Administrators",
          "Intended Audience :: Developers",
          "Operating System :: POSIX",
          "Programming Language :: C",
          "Programming Language :: Python",
          "Programming Language :: YACC",
          "License :: OSI Approved :: MIT License",
          "Topic :: Software Development :: Libraries :: Python Modules",
          "Topic :: System :: Systems Administration :: Authentication/Directory",
          ]
      )

