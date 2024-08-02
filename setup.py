from setuptools import setup, find_packages

setup(
    name='dftpl',
    version='0.0.1',
    description='PyDFT analyzer for plaso CSV file',
    author='Hudan Studiawan',
    author_email='studiawan@gmail.com',
    url='https://github.com/studiawan/dftpl',
    packages=find_packages(include=['dftpl', 'dftpl.*']),
    entry_points={
        'console_scripts': [
            'dftpl = dftpl.dftpl:main',
        ]  
    },
    install_requires=['pytest', 'PyYAML'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
)
