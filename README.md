# OP-TEE sanity testsuite
The optee_test git contains the source code for the TEE sanity
testsuite in Linux using the ARM(R) TrustZone(R) technology.
It is distributed under the GPLv2 and BSD 2-clause open-source
licenses.
For a general overview of OP-TEE, please see the
[Notice.md](Notice.md) file.

## License
The client applications (`optee_test/host/*`) are provided under the
[GPL-2.0](http://opensource.org/licenses/GPL-2.0) license.
The user TAs (`optee_test/ta/*`) are provided under the
[BSD 2-Clause](http://opensource.org/licenses/BSD-2-Clause) license.


## Get and build the software

### HOWTO build the testsuite
#### Standard tests
	- Easiest way is to use a helper script like the ones generated when
	  running either setup_fvp_optee.sh or setup_qemu_optee.sh in the
	  [optee_os](https://github.com/OP-TEE/optee_os/tree/master/scripts)
	  git. If you decide to not use those script you need to set a couple of
	  environment variables before invoking make. Pay attention to that
	  `CROSS_COMPILE_HOST` and `CROSS_COMPILE_TA` doesn't have to be the
	  same. In some setups (ARMv8-A on FVP for example) you will point
	  `CROSS_COMPILE_TA` to a 32-bit compiler, while you point the
	  `CROSS_COMPILE_HOST` to a 64-bit compiler.

	  ```
	  # The path to the toolchain
	  export PATH=$HOME/devel/toolchains/aarch32/bin:$PATH

	  # The compiler used to compile xtest, i.e, the host binary
	  export CROSS_COMPILE_HOST=arm-linux-gnueabihf-

	  # The compiler used to compile the Trusted Applications
	  export CROSS_COMPILE_TA=arm-linux-gnueabihf-

	  # The path to the TA-dev-kit created when you have built optee_os. It
	  # is important to use this, since it contains flags etc that will be
	  # used when building Trusted Applications for your target.
	  export TA_DEV_KIT_DIR=$DEV_PATH/optee_os/out/arm-plat-vexpress/export-user_ta

	  # You must specify where the binaries and intermediate build files for
          # optee_test should be located. We're suggesting that you put them as
	  # stated just below.
	  export O=$OPTEE_DEV_PATH/optee_test/out/${ARCH}-plat-${CFG_PLATFORM}
	  ```

#### Extended test (GlobalPlatform tests)
        FIXME: This needs to be updated to make sure it matches the recent
	changes where we are using the ta-dev-kit from the optee_os git (
	please check previous versions of this particular file to find the old
	instructions).

### HOWTO run xtest

	# all xtest
	boot and execute on your target
	$ modprobe optee_armtz
	$ tee-supplicant &
	$ xtest

	# single xtest
	boot and execute on your target
	$ modprobe optee_armtz
	$ tee-supplicant &
	$ xtest <testnumber> (i.e.: xtest 1001)

	# family xtest (i.e.: Family 1000)
	boot and execute on your target
	$ modprobe optee_armtz
	$ tee-supplicant &
	$ xtest _<family> (i.e.: xtest _1)

#### Compiler flags
To be able to see the full command when building you could build using following
flag:

`$ make V=1`

To state where build files are stored use the `O` flag.

`$ make O=$HOME/foo`

By default `optee_test` expects that `optee_client` is located at the same
folder level. However if you build optee_client in another location, then you
also would need to use (or export) the following flag:

`$ make OPTEE_CLIENT_PATH=$HOME/my_new_location`

## Coding standards
In this project we are trying to adhere to the same coding convention as used in
the Linux kernel (see
[CodingStyle](https://www.kernel.org/doc/Documentation/CodingStyle)). We achieve this by running
[checkpatch](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/scripts/checkpatch.pl) from Linux kernel.
However there are a few exceptions that we had to make since the code also
follows GlobalPlatform standards. The exceptions are as follows:

- CamelCase for GlobalPlatform types are allowed.
- And we also exclude checking third party code that we might use in this
  project, such as LibTomCrypt, MPA, newlib (not in this particular git, but
  those are also part of the complete TEE solution). The reason for excluding
  and not fixing third party code is because we would probably deviate too much
  from upstream and therefore it would be hard to rebase against those projects
  later on (and we don't expect that it is easy to convince other software
  projects to change coding style).

### checkpatch
Since checkpatch is licensed under the terms of GNU GPL License Version 2, we
cannot include this script directly into this project. Therefore we have
written the Makefile so you need to explicitly point to the script by exporting
an environment variable, namely CHECKPATCH. So, suppose that the source code for
the Linux kernel is at `$HOME/devel/linux`, then you have to export like follows:

	$ export CHECKPATCH=$HOME/devel/linux/scripts/checkpatch.pl
thereafter it should be possible to use one of the different checkpatch targets
in the [Makefile](Makefile). There are targets for checking all files, checking
against latest commit, against a certain base-commit etc. For the details, read
the [Makefile](Makefile).
