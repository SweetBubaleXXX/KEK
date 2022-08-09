from setuptools import find_packages, setup

from KEK import __version__

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(name="gnukek",
      version=__version__,
      author="SweetBubaleXXX",
      license="GNU General Public License v3.0",
      description="Kinetic Encryption Key",
      long_description=long_description,
      long_description_content_type="text/markdown",
      url="https://github.com/SweetBubaleXXX/KEK",
      project_urls={
          "Documentation": "https://gnukek.readthedocs.io/en/latest/",
          "Source": "https://github.com/SweetBubaleXXX/KEK",
          "Bug Tracker": "https://github.com/SweetBubaleXXX/KEK/issues",
      },
      classifiers=[
          "Development Status :: 4 - Beta",
          "Topic :: Security :: Cryptography",
          "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
          "Programming Language :: Python :: 3",
          "Operating System :: OS Independent",
      ],
      packages=find_packages(include=["KEK"]),
      package_data={
          "KEK": ["py.typed"]
      },
      install_requires=[
          "cryptography>=35.0.0"
      ],
      extras_require={
          "dev": [
              "mypy",
              "pycodestyle",
              "pylint",
              "pytest"
          ],
          "build": [
              "build",
              "twine"
          ],
          "docs": [
              "sphinx",
              "sphinx_rtd_theme"
          ]
      },
      python_requires=">=3.7",
      test_suite="tests")
