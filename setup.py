"""Installable SPK runtime: optional Cython compilation of spk_engine.pipeline into a binary extension."""
from setuptools import Extension, find_packages, setup

try:
    from Cython.Build import cythonize
except ImportError:
    cythonize = None

_EXT = None
if cythonize is not None:
    _EXT = cythonize(
        [
            Extension('spk_engine.pipeline', ['spk_engine/pipeline.py']),
            Extension('spk_engine.run_config', ['spk_engine/run_config.py']),
        ],
        compiler_directives={'language_level': '3', 'embedsignature': True},
    )

setup(
    name='spk-engine',
    version='0.1.0',
    description='Orchestration runtime for the SPK KD-tree demo (pipeline compiles to .so when Cython is present).',
    packages=find_packages(include=['spk_engine*']),
    python_requires='>=3.9',
    install_requires=[
        'phe',
        'numpy>=1.20',
    ],
    ext_modules=_EXT,
)
