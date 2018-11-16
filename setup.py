from setuptools import setup, find_packages

setup(
    name='mitmproxy-image',
    version='1.0.0',
    descriptioin='Download image using mitmproxy',
    long_description=__doc__,
    long_description_content_type="text/markdown",
    author='Rachmadani Haryono',
    author_email='Rachmadani Haryono',
    license='MIT',
    url='https://github.com/rachmadaniHaryono/mitmproxy-image',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    python_requires='>=3.5',
    install_requires=[
        'Flask-SQLAlchemy==2.3.2',
        'mitmproxy==4.0.4',
        'SQLAlchemy-Utils==0.33.6',
        'SQLAlchemy==1.2.14',
    ],
    extras_require={
        'dev': [
            'flake8==3.6.0',
            'flask-shell-ipython==0.3.1',
            'ipython==7.1.1',
            'pdbpp==0.9.2',
            'Pillow==5.3.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'mitmproxy-image = mitmproxy_image.__main__:cli']
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP :: Indexing/Search',
        'Topic :: Utilities'
    ]
)
