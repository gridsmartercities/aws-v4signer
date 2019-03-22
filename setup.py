from setuptools import setup, find_packages

LONG_DESCRIPTION = open('README.md').read()

setup(name='aws-v4signer',
      version='0.3',
      description='A python class to get the headers needed for v4 signing an AWS request',
      long_description=LONG_DESCRIPTION,
      long_description_content_type="text/markdown",
      url='https://github.com/gridsmartercities/aws-v4signer',
      author='Grid Smarter Cities',
      author_email='open-source@gridsmartercities.com',
      license='MIT',
      classifiers=['Intended Audience :: Developers',
                   'Development Status :: 3 - Alpha',
                   'Programming Language :: Python :: 3',
                   'License :: OSI Approved :: MIT License',
                   'Operating System :: OS Independent',
                   'Natural Language :: English'
                   ],
      keywords='aws python v4 signature',
      packages=find_packages(exclude=('tests', 'examples')),
      install_requires=[],
      zip_safe=False
      )
