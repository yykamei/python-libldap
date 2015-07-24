from setuptools import setup, find_packages, Extension

ext_module = Extension('_libldap',
                       sources=['Modules/_libldap.c',
                                'Modules/_libldap_utils.c',
                                'Modules/_libldap_bind.c',
                                'Modules/_libldap_search.c',
                                'Modules/_libldap_result.c',
                                'Modules/_libldap_add.c',
                                ],
                       libraries=['ldap'],
                       extra_compile_args=['-g', '-O0'])


setup(name='libldap',
      author='Yutaka Kamei',
      author_email='kamei@ykamei.net',
      version='0.0.4',
      description='A Python binding for libldap',
      ext_modules=[ext_module],
      packages=find_packages('Lib'),
      package_dir={'': 'Lib'},
      py_modules=['libldap'],
)
