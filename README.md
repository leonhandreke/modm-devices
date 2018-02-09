# Curated data on AVR and STM32 devices

This repository contains tools for extracting data from vendor sources,
filtering and reformatting them into a vendor-independent format.

This data is used by [the modm project][modm-io] to generate
its Hardware Abstraction Layer (HAL), startup code and additional support tools.
Please have a look [at modm's platform modules][modm-platform] for examples on
how to use this data.

These tools and this data set is maintained and curated by
[@salkinium][] only at [modm-io/modm-devices][modm-devices].
It is licensed under the MPLv2 license.

Currently data on all STM32 families (except STM32H7) is available, as well as
all AVR devices (most of which are missing GPIO data though).
Please open an issue or better yet a pull request for addititional support.


### TL;DR

```sh
git clone --recursive --depth=1 https://github.com/modm-io/modm-devices.git
cd modm-devices/tools/generator
# Extract and generate STM32 device data
make extract-data-stm32
make generate-stm32
# Extract and generate AVR device data
make extract-data-avr
make generate-avr
```

You need Python3 with lxml and deepdiff packages, as well as Java (for `javac`/`java`).


### Background

The device data idea originally cames from [xpcc](http://xpcc.io), which is the
predecessor to modm. At the time we wanted to remove some of the repretitive
steps for building a HAL for AVR and STM32 devices and we chose to extract some
common data and collapse some peripheral drivers into a Jinja2 template.

This eventually evolved from manually curated device data to full blown generated
device data when we found machine readable data sources from vendors.
For AVRs, we use the Atmel Target Description Files and for STM32, we use
internal data extracted from the CubeMX code generator.

Thus the Device File Generator (DFG) was born. The DFG has been rewritten for
modm to make it more maintainable and flexible as well as handling edge cases
much better.

We've separated the device data from modm, so that it becomes easier for YOU
to use this data for your own purposes. See my [talk on modm][modm-talk] for details.

[![][modm-talk-preview]][modm-talk]


### Data quality

The quality of the resulting device data obviously depend heavily on the quality
of the input data. I reluctantly maintain a manual patch list for the bugs I've
encountered in the vendor sources, that I don't want to write a fix for in the DFG.
I have sent some of these patches to a contact in ST, however, every new release
of CubeMX changes a lot of data and can reintroduce some of these bugs.
I don't have a contact at Atmel to send bug reports to.

In addition, the CubeMX and AVR data does not contain some very important
information, which has to be assembled manually from hundreds of datasheets and
is then injected into the DFG. This is extremely labor intensive.

Since we're on this topic, let me make this clear: I DO NOT WORK FOR YOU!
I do not like to spend hours upon hours copying this additional data out of
datasheets, so please do not open an issue *asking* for more raw data.

You may of course open an issue about wrong data, but don't expect me to fix it
for you. Instead please open a pull request that fixes the problem in the DFG.
I only accept patches to the raw data, not the device files.
All fixes MUST BE REPRODUCIBLE by the DFG!

*DO NOT UNDER ANY CIRCUMSTANCES PUBLISH THE EXTRACTED DATA FROM CUBEMX ANYWHERE!*
It is subject to ST's copyright and you are not allowed to distribute it!


### Data format

I initially wanted to format this data as [device trees][device-tree],
however, since it is so tied to the Linux kernel, there isn't (or wasn't) much
tool support available at the time (though now there is a Python parser in Zephyr),
so we wrote our own tree-based format, which we called "device files" since we're
so creative. It allows lossless overlaying of data trees to reduce the amount of
duplicate data noise which makes it easier to comprehend as a human.

I do not intent to standardize this **format**, it may change at any time for any
reason. You must not rely on this data **FORMAT**!
I'm not at all interested in discussions about this data format, except when
this format needs to change to represent data correctly.

Instead, you should write your **own formatter** of this data, so that you have
much better control over what your tools are expecting!
For modm we convert this format to a Python dictionary tree, so the format can
change however it wants, as long as the internal representation is consistent.

Please understand that extracting and curating this data is a lot of work on
its own, and I really don't intend to bikeshed on how to format them.
So, if you need this data in the form of a Device Tree, please write your own
data converter and maintain it yourself!


[modm-talk-preview]: https://gist.githubusercontent.com/salkinium/43a303c61b5e15e9a91d34116ea5d07c/raw/ab836c051039421e7bb0875ec9cb93c2d3f76236/modm-devices.png
[modm-talk]: http://salkinium.com/talks/modm_embo17.pdf
[modm-platform]: https://github.com/modm-io/modm/tree/develop/src/modm/platform
[device-tree]: https://www.devicetree.org
[@salkinium]: http://github.com/salkinium
[modm-devices]: https://github.com/modm-io/modm-devices
[modm-io]: https://github.com/modm-io