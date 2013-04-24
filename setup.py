from distutils.core import setup, Extension

setup(
    ext_modules=[
                Extension("kadmin",
                    libraries       = ["krb5", "kadm5clnt"],
                    library_dirs    = ["/usr/lib64/"], 
                    include_dirs    = ["/usr/include/et/"],
                    sources         = ["./kadmin.c", "./PyKAdminObject.c", "./PyKAdminPrincipalObject.c"],
                    
                )
        ]
    )
    #/usr/lib64/libkadm5clnt_mit.so
