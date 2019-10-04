# ARP Net Speed Controller

## Get & Compile

```bash
git clone https://github.com/RileyWen/arp-net-speed-controller.git
cd arp-net-speed-controller
cmake -DCMAKE_BUILD_TYPE=Debug -G "CodeBlocks - Unix Makefiles" .
make -j 4
```

-----------

## Before Running

- Since `TCP Segmentation` has yet to implement,
  you should use `ethtool` to turn off **all** *receive offload* on
  the network interface. e.g `sudo ethtool -K wlan0 gro off`
- Since the forwarding part is based on `libpcap`, you should turn off
  system **kernel forwarding**. e.g. `sudo sysctl -w net.ipv4.ip_forward=0`

-----------

## How to Use

```text
-T --target-ip=<target IP>             'Target' is the device you want to attack
-t --target-mac=<target MAC>
-G --gateway-ip=<gateway IP>           'Gateway' is often the router in your subnet
-g --gateway-mac=<gateway MAC>
-S --self-ip=<IP of this device>       'Self' means the device running this program
-s --self-mac=<MAC of this device>
-h --help                              Print this help info
```

-----------

## Running Example
[![asciicast](https://asciinema.org/a/272451.svg)](https://asciinema.org/a/272451)
