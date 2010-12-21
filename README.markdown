sha256crack
===========

*sha256crack* cracks passwords hashed with the SHA‐256 algorithm via brute
force hash calculation.  It calculates hashes for all possible strings in
a given range of length composed of characters in a given character set.

Depending on options passed, *sha256crack* may run on the host CPU or an
OpenCL device, such as the GPU.

Requirements
============

Currently, only Mac OS X 10.6 is supported.

Support for other systems will be added.  This will require modifying
the Makefile and possibly some minor changes to the code.

Installation
============

Use

	make

to compile.  The resulting binary will be put in the build/ directory.

Optionally, you may choose to install the program via:

	sudo make install

To uninstall, run:

	sudo make uninstall

Usage
=====

Type

	sha256crack --help

for a list of options.

If you have installed the program, view the manual page via:

	man sha256crack

Otherwise, use

	nroff -man sha256crack.1 | less

to view the manual page.
