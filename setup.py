from setuptools import setup, find_packages, Extension

ext_module = Extension('_libldap',
                       sources=['Modules/_libldap.c',
                                'Modules/_add.c',
                                'Modules/_bind.c',
                                'Modules/_result.c',
                                'Modules/_search.c',
                                'Modules/_utils.c',
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
