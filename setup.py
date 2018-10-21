from pathlib import Path
from setuptools import setup, find_packages


long_description_src = Path(__file__).parent / 'README.md'


setup(
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    description='helper for working with jenkins update-center.json',
    extras_require={
        'dev': [
            'pylint ~= 2.1.1',
            'pytest ~= 3.9.1',
            'twine ~= 1.11.0',
            'wheel ~= 0.32.2',
        ],
    },
    install_requires=[
        'cryptography ~= 2.3.1',
    ],
    license='MIT',
    long_description=long_description_src.read_text(encoding='utf-8'),
    long_description_content_type='text/markdown',
    name='jenkins-update-center-helper',
    packages=find_packages(),
    python_requires='~=3.6',
    url='https://github.com/chrahunt/python-jenkins-update-center-helper',
    version='0.1.0',
)
