#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup, Extension
from distutils.util import execute, newer
from distutils.spawn import spawn


if newer('getdate.y', 'getdate.c'):
    execute(spawn, (['bison', '-y', '-o', 'getdate.c', 'getdate.y'],))

setup(name='kadmin',
      description='Python module for kerberos admin (kadm5)',
      url='https://github.com/russjancewicz/python-kadmin',
      author='Russell Jancewicz',
      author_email='russell.jancewicz@gmail.com',
      #ext_package="python-kadmin",
      ext_modules=[
          Extension(
              "kadmin",
              libraries=["krb5", "kadm5clnt"],
              include_dirs=["/usr/include/et/"],
              sources=[
                  "./kadmin.c",
                  "./PyKAdminErrors.c",
                  "./PyKAdminObject.c",
                  "./PyKAdminIterator.c",
                  "./PyKAdminPrincipalObject.c",
                  "./PyKAdminPolicyObject.c",
                  "getdate.c"
                  ]
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
          "Topic :: Software Development :: Libraries :: Python Modules",
          "Topic :: System :: Systems Administration :: Authentication/Directory",
          ]
      )
