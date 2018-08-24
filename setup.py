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
      description='Python module for kerberos admin (kadm5)- forked form russjancewicz/python-kadmin',
      url='https://github.com/integrateai/python-kadmin',
      download_url='https://github.com/integrateai/python-kadmin/tarball/v0.1.1',
      author='Colin Toal',
      author_email='colin@integrate.ai',
      license='MIT',
      ext_modules=[
          Extension(
              "kadmin",
              libraries=["krb5", "kadm5clnt", "kdb5"],
              include_dirs=["/usr/include/"],
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

#setup(name='python-kadmin-local',
#      version='0.1.1',
#      description='Python module for kerberos admin (kadm5) via root local interface',
#      url='https://github.com/integrateai/python-kadmin',
#      download_url='https://github.com/integrateai/python-kadmin/tarball/v0.1.1',
#      author='Colin Toal',
#      author_email='colin@integrate.ai',
#      license='MIT',
#      ext_modules=[
#          Extension(
#              "kadmin_local",
#              libraries=["krb5", "kadm5srv", "kdb5"],
#              include_dirs=["/usr/include/"],
#              sources=[
#                  "src/kadmin.c",
#                  "src/PyKAdminErrors.c",
#                  "src/PyKAdminObject.c",
#                  "src/PyKAdminIterator.c",
#                  "src/PyKAdminPrincipalObject.c",
#                  "src/PyKAdminPolicyObject.c",
#                  "src/PyKAdminCommon.c",
#                  "src/PyKAdminXDR.c",
#                  "src/getdate.c"
#                  ],
#              define_macros=[('KADMIN_LOCAL', '')]
#              )
#          ],
#      classifiers=[
#          "Development Status :: 4 - Beta",
#          "Environment :: Console",
#          "Intended Audience :: System Administrators",
#          "Intended Audience :: Developers",
#          "Operating System :: POSIX",
#          "Programming Language :: C",
#          "Programming Language :: Python",
#          "Programming Language :: YACC",
#          "License :: OSI Approved :: MIT License",
#          "Topic :: Software Development :: Libraries :: Python Modules",
#          "Topic :: System :: Systems Administration :: Authentication/Directory",
#          ]
#      )

setup(
    name="pykerberize",
    version="0.1.0",
    author="Colin Toal",
    author_email="colin@integrate.ai",
    description="Looks up principal (creates if necessary), and generates keytab",
    url="https://github.com/integrateai/python-kadmin",
    packages=['pykerberize', 'pykerberize.test'],
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
    install_requires=[
        "boto3"
    ]
)
