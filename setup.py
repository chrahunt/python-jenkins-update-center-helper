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
    extra_requires=[
        'dev': [
            'twine >= 1.11.0',
        ],
    ],
    install_requires=[],
    license='MIT',
    long_description=long_description_src.read_text(encoding='utf-8'),
    long_description_content_type='text/markdown',
    name='jenkins-update-center-helper',
    packages=find_packages()
    python_requires='~=3.6',
    url='https://github.com/chrahunt/python-jenkins-update-center-helper',
    version='0.1.0',
)