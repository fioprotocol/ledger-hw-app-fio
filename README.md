# FIO Ledger App

FIO Ledger App for Ledger Nano S


## Building

### Loading the app

`make load`

Builds and loads the application into connected device. Just make sure to close the Ledger app on the device before running the command.


### Debug version

In `Makefile`, uncomment

    #DEVEL = 1
    #DEFINES += HEADLESS

also comment out

    DEFINES += RESET_ON_CRASH

and then run `make clean load`.

### Setup

Make sure you have:
- SDK >= 2.0.0
- MCU >= 1.11

Environment setup and developer documentation is sufficiently provided in Ledger’s [Read the Docs](https://developers.ledger.com/docs/nano-app/quickstart/).

You want a debug version of the MCU firmware (but it blocks SDK firmware updates, so for the purpose of upgrading SDK, replace it temporarily with a non-debug one). Instructions for swapping MCU versions: https://github.com/LedgerHQ/ledger-dev-doc/blob/master/source/userspace/debugging.rst

### Troubleshooting connection problems

The quickstart guide's script sets up your udev rules, but there still might be problems.
- https://support.ledger.com/hc/en-us/articles/115005165269-Fix-connection-issues

## Development

To learn more about development process and individual commands, [check the desing doc](doc/design_doc.md).

## Deploying

The build process is managed with [Make](https://www.gnu.org/software/make/).

### Make Commands

* `load`: Load signed app onto the Ledger device
* `clean`: Clean the build and output directories
* `delete`: Remove the application from the device
* `build`: Build obj and bin api artefacts without loading
* `format`: Format source code.

See `Makefile` for list of included functions.

## How to get a transaction body computed by Ledger

Ordinarily, Ledger computes a rolling hash of the serialized transaction body, but the body itself is not available. It is possible to acquire it from the development build by going through the following steps:

1. [Install debug MCU](https://ledger.readthedocs.io/en/latest/userspace/debugging.html#application-debug) on your Ledger Nano S device.

2. Install the debug version of FIO app (see above).

3. Install `usbtool` and turn on [console printing](https://ledger.readthedocs.io/en/latest/userspace/debugging.html#console-printing).

4. Send a single `signTx` call to Ledger (e.g. by running `yarn test-integration --grep "<some-signTx-test>"`).

5. After the call is processed, the terminal running console printing now contains all log messages resulting from that `signTx` call. (See the `TRACE*` macros.). You can build the transactions using data between logged within sha_256_append function.

