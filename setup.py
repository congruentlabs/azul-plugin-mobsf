#!/usr/bin/env python3
"""Setup script."""
import os

from setuptools import setup


def open_file(fname):
    """Open and return a file-like object for the relative filename."""
    return open(os.path.join(os.path.dirname(__file__), fname))


setup(
    name="azul-plugin-mobsf",
    description="Submit binaries to MobSF static & dynamic analysis",
    long_description=open_file("README.md").read(),
    author="",
    author_email="",
    url="https://github.com/Azul/_git/azul-plugin-mobsf",
    packages=["azul_plugin_mobsf"],
    include_package_data=True,
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Analysis",
    ],
    entry_points={
        "console_scripts": [
            "azul-plugin-mobsf = azul_plugin_mobsf.main:main",
        ]
    },
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    install_requires=[r.strip() for r in open_file("requirements.txt") if not r.startswith("#")],
)
