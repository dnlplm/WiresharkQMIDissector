# Wireshark QMI Dissector
Wireshark Dissector for Qualcomm MSM Interface (QMI) Protocol v0.2

Copyright (c) 2017 Daniele Palmas <dnlplm@gmail.com>

Based on:

- Wireshark Dissector for Qualcomm MSM Interface (QMI) Protocol v0.1
  Copyright (c) 2012 Ilya Voronin <ivoronin@gmail.com>
  https://gist.github.com/ivoronin/2641557

- Code Aurora Forum's BSD/GPL licensed code:
  http://www.codeaurora.org/contribute/projects/gobi/

- freedesktop.org libqmi
  https://www.freedesktop.org/wiki/Software/libqmi/

## Usage
- Clone libqmi repository

- Generate the dissector with:

    generate_lua.py &lt;libqmi json directory path&gt;

    to create qmi_dissector_gen.lua

    Script runs with python 3.x or 2.x. For python <3.4 install pathlib 
using pip install pathlib.

Once the dissector has been generated:

LINUX

1. Make sure to have usbmon support enabled

2. Find device in the lsusb output, e.g.:

    $ lsusb
    ...
    Bus 003 Device 022: ID 1bc7:1201 Telit Wireless Solutions
    ...

3. Run wireshark:

    $ wireshark -X lua_script:qmi_dissector_gen.lua

4. Collect log in the appropriate usbmon device (3 in the example) and appply qmi filter

WINDOWS

1. Make sure to have usbpcap installed

2. Find device in USBPcapCMD.exe output, e.g.:

    C:\Program Files\USBPcap\USBPcaCMD.exe
    ...
    2 \\.\USBPcap4
      \??\USB#ROOT_HUB20#4&244e1552&0#<f18a0e88-c30c-11d0-8815-00a0c906bed8>
        [Port 2] Telit USB  Composite Device 0x1201

3. Run wireshark:

    "C:\Program Files\Wireshark\Wireshark.exe" -X lua_script:qmi_dissector_gen.lua

4. Collect log in the appropriate usbpcap device (4 in the example)

## Contributors

Daniele Palmas <dnlplm@gmail.com>

## License

GPL V3

