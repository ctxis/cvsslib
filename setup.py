from setuptools import setup
import sys

requirements = []

# Enum34 fails in Python 3.5 (and not needed in 3.4), so skip it.
if sys.version_info < (3, 4):
    requirements.append("enum34")

setup(
    name='cvsslib',
    version='0.1',
    packages=['cvsslib', 'cvsslib.cvss2', 'cvsslib.cvss3', 'cvsslib.contrib'],
    url='',
    license='',
    author='Tom',
    author_email='tom.forbes@contextis.co.uk',
    description='CVSS 2/3 utilities',
    install_requires=requirements,
    entry_points={
        'console_scripts': ['cvss=cvsslib.command:main'],
    }
)
