import os
from setuptools import setup


os.chdir(os.path.abspath(os.path.dirname(__file__)))


req = ['pyuac']
setup(name='reprozip-windows',
      version='0.1',
      packages=['reprozip_windows'],
      entry_points={
          'console_scripts': [
              'reprozip-windows = reprozip_windows.main:main']},
      install_requires=req,
      description="Tool enabling reproducible experiments (windows packer)",
      author="Remi Rampin, Fernando Chirigati, Dennis Shasha, Juliana Freire",
      author_email='dev@reprozip.org',
      maintainer="Remi Rampin",
      maintainer_email='remi@rampin.org',
      url='https://www.reprozip.org/',
      project_urls={
          'Homepage': 'https://github.com/ViDA-NYU/reprozip',
          'Documentation': 'https://docs.reprozip.org/',
          'Examples': 'https://examples.reprozip.org/',
          'Say Thanks': 'https://saythanks.io/to/remram44',
          'Source': 'https://github.com/ViDA-NYU/reprozip',
          'Tracker': 'https://github.com/ViDA-NYU/reprozip/issues',
      },
      long_description="Tool enabling reproducible experiments (windows packer)",
      license='BSD-3-Clause',
      keywords=['reprozip', 'reprounzip', 'reproducibility', 'provenance',
                'vida', 'nyu'],
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 3',
          'Operating System :: Microsoft :: Windows',
          'Topic :: Scientific/Engineering',
          'Topic :: System :: Archiving'])
