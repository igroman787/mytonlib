#!/usr/bin/env python3
# -*- coding: utf_8 -*-

from distutils.core import setup
from os.path import dirname, join
from os import listdir


my_dir = dirname(__file__)
print("listdir:", listdir(my_dir))
with open(join(my_dir, "requirements.txt")) as file:
    install_requires = file.read().split('\n')
with open(join(my_dir, "README.md")) as file:
    long_description = file.read()
#end with

setup(name = "mytonlib",
	version = "0.7.1",
	description = "Native library for working with TON (The Open Network)",
	author = "Igroman787",
	url="https://github.com/igroman787/mytonlib",
	packages=["mytonlib"],
	install_requires = install_requires,
    long_description = long_description,
	long_description_content_type = "text/markdown",
	python_requires = ">=3.7"
)
