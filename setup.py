# Author Ondrej Barta
# git@ondrej.it
# Copyright 2022

from distutils.core import setup

from thumbor_crypto import __version__


TESTS_REQUIREMENTS = [
]


setup(
    name="thumbor_crypto",
    version=__version__,
    description="thumbor_crypto provides encryption handler for thumbor",
    long_description="thumbor_crypto encrypts all thumbor parameters in the query string",
    keywords=(
        "thumbor encryption"
    ),
    author="Ondrej Barta",
    author_email="git@ondrej.it",
    url="https://github.com/OndrejIT/thumbor-crypto",
    license="MIT",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Multimedia :: Graphics :: Presentation",
    ],
    packages=["thumbor_crypto"],
    package_dir={"thumbor_crypto": "thumbor_crypto"},
    include_package_data=True,
    package_data={"": ["*.xml"]},
    install_requires=[
        "thumbor>=7.0.0",
        "pycryptodome>=3.11.0",
    ],
    extras_require={"tests": TESTS_REQUIREMENTS},
    entry_points={
        "console_scripts": [],
    },
)
