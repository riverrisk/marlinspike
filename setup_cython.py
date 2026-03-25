"""Cython build script — compiles MarlinSpike modules to .so shared objects."""
from Cython.Build import cythonize
from setuptools import setup

setup(
    ext_modules=cythonize(
        ["_ms_engine.py", "_auth.py", "_models.py", "_config.py"],
        compiler_directives={"language_level": "3"},
    ),
)
