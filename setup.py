try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


requirements = [
    "pykd",
    #"vivisect", # install from https://github.com/williballenthin/vivisect
    "winappdbg"
]

description = "Utilities and plugins for debugger scripting."

setup(
    name='flaredbg',
    version='0.1.0',
    description=description,
    long_description=description,
    author="Tyler Dean",
    author_email='tyler.dean@fireeye.com',
    url='https://github.com/fireeye/flare-dbg',
    packages=[
        'flaredbg',
        'examples',
    ],
    include_package_data=True,
    install_requires=requirements,
    zip_safe=False,
)
