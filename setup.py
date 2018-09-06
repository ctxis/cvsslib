from setuptools import setup

setup(
    name='cvsslib',
    version='0.6.0',
    packages=['cvsslib', 'cvsslib.cvss2', 'cvsslib.cvss3', 'cvsslib.contrib'],
    url='https://github.com/ctxis/cvsslib',
    license='GPL',
    author='Tom',
    author_email='tom.forbes@contextis.co.uk',
    description='CVSS 2/3 utilities',
    long_description='A library for manipulating CVSS v2 and v3 vectors. Visit the github page '
                     '(https://github.com/ctxis/cvsslib) for examples and documentation.',
    python_requires='>=3.5',
    entry_points={
        'console_scripts': ['cvss=cvsslib.command:main'],
    },
    classifiers=[
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5'],
)
