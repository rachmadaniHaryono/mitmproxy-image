"""
Method to get program version is based on follwoing url:
https://packaging.python.org/guides/single-sourcing-package-version/
"""
import pathlib
import typing

from setuptools import find_packages, setup

version: typing.Dict[str, typing.Any] = {}
with (pathlib.Path(__file__).parent / "mitmproxy_image" / "version.py").open() as fp:
    exec(fp.read(), version)


TEST = [
    "flake8>=3.6.0",
    "mypy>=0.761",
    "pytest",
    "pytest-cov",
    "pytest-flake8",
    "pytest-mypy",
]


setup(
    name="mitmproxy-image",
    version=version["__version__"],
    description="Download image using mitmproxy",
    long_description=__doc__,
    long_description_content_type="text/markdown",
    author="Rachmadani Haryono",
    author_email="foreturiga@gmail.com",
    license="MIT",
    url="https://github.com/rachmadaniHaryono/mitmproxy-image",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    python_requires=">=3.6",
    install_requires=[
        "hydrus-api>=2.14.3",
        "ipdb>=0.13.3",
        "mitmproxy>=7.0.0",
        "more-itertools>=8.7.0",
        "Pillow>=5.3.0",
        "python-json-logger>=2.0.1",
        "python-magic>=0.4.22",
        "PyYAML>=5.3.1",
        "requests>=2.21.0",
    ],
    extras_require={
        "dev": [
            "pdbpp>=0.9.2",
        ]
        + TEST,
        "test": TEST,
    },
    entry_points={"console_scripts": ["mitmproxy-image = mitmproxy_image.__main__:mitmproxy"]},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Internet :: WWW/HTTP :: Indexing/Search",
        "Topic :: Utilities",
    ],
)
