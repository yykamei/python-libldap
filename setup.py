# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

# Required Python libraries:
#   - setuptools
#
# Required C libraries:
#   - libldap
#   - libssl

from setuptools import setup, find_packages, Extension

ext_module = Extension('_libldap',
                       sources=['Modules/libldap.c',
                                'Modules/common.c',
                                'Modules/bind.c',
                                'Modules/unbind.c',
                                'Modules/search.c',
                                'Modules/add.c',
                                'Modules/modify.c',
                                'Modules/delete.c',
                                'Modules/rename.c',
                                'Modules/compare.c',
                                'Modules/abandon.c',
                                'Modules/whoami.c',
                                'Modules/passwd.c',
                                'Modules/cancel.c',
                                'Modules/start_tls.c',
                                'Modules/set_option.c',
                                'Modules/result.c',
                                ],
                       libraries=['ldap'],
                       include_dirs=['/usr/include', '/usr/local/include'],
                       extra_compile_args=['-g', '-O0'])

setup(name='python-libldap',
      license='MIT',
      author='Yutaka Kamei',
      author_email='kamei@ykamei.net',
      url='https://github.com/yykamei/python-libldap',
      version='0.6.1',
      description='A Python binding for libldap',
      ext_modules=[ext_module],
      packages=find_packages('Lib'),
      package_dir={'': 'Lib'},
      py_modules=['libldap'],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: C',
          'Programming Language :: Python :: 3.4',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
      ],
)
