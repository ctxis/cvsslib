from setuptools import setup

setup(
    name='cvsslib',
    version='0.1',
    packages=['cvsslib', 'cvsslib.cvss2', 'cvsslib.cvss3', 'cvsslib.contrib'],
    url='',
    license='',
    author='Tom',
    author_email='tom.forbes@contextis.co.uk',
    description='CVSS 2/3 utilities',
    entry_points={
        'console_scripts': ['cvss=cvsslib.command:main'],
    }
)
