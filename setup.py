# -*- coding: utf-8 -*-
# Copyright (C) 2015 Yutaka Kamei

from setuptools import setup, find_packages, Extension

ext_module = Extension('_libldap',
                       sources=['Modules/libldap.c',
                                'Modules/common.c',
                                'Modules/bind.c',
                                'Modules/search.c',
                                'Modules/add.c',
                                'Modules/modify.c',
                                'Modules/delete.c',
                                'Modules/result.c',
                                ],
                       libraries=['ldap'],
                       extra_compile_args=['-g', '-O0'])

setup(name='libldap',
      license='MIT',
      author='Yutaka Kamei',
      author_email='kamei@ykamei.net',
      version='0.0.4',
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
