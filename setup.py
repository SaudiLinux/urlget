#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name="urlget",
    version="1.0.0",
    description="أداة اختبار أمان الويب متعددة الوظائف",
    author="SayerLinux",
    author_email="SaudiLinux1@gmail.com",
    url="https://github.com/SaudiLinux",
    packages=find_packages(),
    install_requires=[
        "requests",
        "selenium",
        "beautifulsoup4",
        "colorama",
        "argparse",
        "dnspython",
        "pyfiglet",
        "webdriver-manager",
        "tqdm",
        "lxml",
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "urlget=urlget.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
)