#!/usr/bin/env python

from distutils.core import setup, Extension

setup(
    ext_modules=[
        Extension(
            "kadmin",
            libraries=["krb5", "kadm5clnt"],
            sources=[
                "./kadmin.c",
                "./PyKAdminErrors.c",
                "./PyKAdminObject.c",
                "./PyKAdminPrincipalObject.c",
                "getdate.c"
                ]
            )
        ]
    )
    #/usr/lib64/libkadm5clnt_mit.so
