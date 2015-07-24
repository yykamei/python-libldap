from distutils.core import setup, Extension

module = Extension('_libldap',
                   sources=['_libldap.c', '_libldap_utils.c'],
                   libraries=['ldap'],
                   extra_compile_args=['-g', '-O0'])

setup(name='ldap',
      version='0.1',
      description='LDAP test library',
      ext_modules=[module]
)
