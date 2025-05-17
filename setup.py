from setuptools import setup, find_packages

setup(
    name='advanced_encryption_tool',
    version='0.1.0',
    description='Advanced AES-256-GCM Encryption Tool with AWS-KMS and HSM support',
    author='Deepayan Dey',
    author_email='pandaaahacker007@gmail.com',
    url='https://github.com/error404-004/advanced_encryption_tool',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    python_requires='>=3.8',
    install_requires=[
        'pycryptodome>=3.17',
        'boto3>=1.26',
        'PyKCS11>=1.5',
        'PyQt6>=6.4',
    ],
    extras_require={
        'dev': ['pytest>=7.0', 'pytest-cov>=4.0'],
    },
    entry_points={
        'console_scripts': [
            'aetool=main:main',  # if you want a CLI entry point (adjust as needed)
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
    ],
)