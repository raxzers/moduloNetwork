# Modulo network (Net_trace): A module to obtain the bytes transmited thru the nic o ethernet port

Proof of concept to obtain the bytes transmited thru the nic o ethernet port for each process

## Installation

This module uses `make` as the building system. To install the dependencies. Please, check the following instructions according to your needs:

```bash
# Ubuntu
sudo apt update
sudo apt install -y \
  clang llvm \
  gcc g++ make \
  libbpf-dev libelf-dev \
  linux-headers-$(uname -r)
```

```bash
# Fedora
sudo yum install -y \
  clang llvm \
  gcc gcc-c++ make \
  elfutils-libelf-devel \
  libbpf libbpf-devel \
  kernel-devel-$(uname -r)
```


### Compiling ModuloIODisk

Compiling Modulo network follows the same process as any make project. This compilation create all the nesesary files tu run.

```bash
make
```


## Running Modulo network

When running this module it has two modes:
 ### Event mode

This mode focuses on capturing individual packets and granularly associating metrics with the process context at the exact moment of transfer.

```bash
make run
```
![runinng example](img/example1.png)

### Bandwith mode

This mode focuses on capturing and aggregating metrics within defined time windows. This operation runs on a separate thread to ensure sampling cycle independence.

```bash
make runBW
```

## Running test

### Event mode

Once the test is finished, exit the execution with `Ctrl+C` to close the module and thus generate the file `measurements_DATE.csv` in the processed_data folder of the module with the general report `reportDATE.txt` .

### Bandwith mode
Once the test is finished, exit the execution with `Ctrl+C` to close the module and thus generate the file `reportDATE.txt` in the  processed_data folder of the module.


## Future work
- prompt to checkout specific process
- integration with EfiMon



### Author

* Gabriel Conejo Valerio

### Official Repository

* Github: https://github.com/raxzers/moduloNetwork
