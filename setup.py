from setuptools import setup, find_packages, Extension

ext_module = Extension('_libldap',
                       sources=['src/_libldap.c',
                                'src/_libldap_utils.c',
                                'src/_libldap_bind.c',
                                'src/_libldap_search.c',
                                'src/_libldap_result.c',
                                'src/_libldap_add.c',
                                ],
                       libraries=['ldap'],
                       extra_compile_args=['-g', '-O0'])


setup(name='libldap',
      author='Yutaka Kamei',
      author_email='kamei@ykamei.net',
      version='0.0.4',
      description='A Python binding for libldap',
      ext_modules=[ext_module],
      packages=find_packages('src'),
      package_dir={'': 'src'},
      py_modules=['libldap'],
)
