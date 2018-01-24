# -*- coding: utf-8 -*-
# Copyright (c) 2013-2016, Niklas Hauser
# Copyright (c)      2016, Fabian Greif
# All rights reserved.

import os
import re
import logging

from ..device_tree import DeviceTree
from ..input.xml import XMLReader

from .stm_identifier import STMIdentifier
from . import stm
from . import stm_peripherals

LOGGER = logging.getLogger('dfg.stm.reader')

class STMDeviceTree:
    """ STMDeviceTree
    This STM specific part description file reader knows the structure and
    translates the data into a platform independent format.
    """
    rootpath = os.path.join(os.path.dirname(__file__), '..', '..', 'raw-device-data', 'stm32-devices', 'mcu')
    cmsis_headers = os.path.join(os.path.dirname(__file__), '..', '..', 'cmsis-header-stm32')
    familyFile = XMLReader(os.path.join(rootpath, 'families.xml'))

    @staticmethod
    def getDevicesFromFamily(family, rootpath=None):
        rawDevices = STMDeviceTree.familyFile.query("//Family[@Name='{}']/SubFamily/Mcu/@RefName".format(family))
        devices = []
        for dev in sorted(rawDevices):
            if len(dev) >= 14: continue;
            shortDev = dev[:12]
            if all(not d.startswith(shortDev) for d in devices):
                devices.append(dev)

        LOGGER.info("Found devices of family '{}': {}".format(family, ", ".join(devices)))
        return devices

    @staticmethod
    def _properties_from_partname(partname):
        p = {}

        deviceNames = STMDeviceTree.familyFile.query("//Family/SubFamily/Mcu[starts-with(@RefName,'{}')]".format(partname))
        comboDeviceName = sorted([d.get('Name') for d in deviceNames])[0]
        device_file = XMLReader(os.path.join(STMDeviceTree.rootpath, comboDeviceName + '.xml'))
        did = STMIdentifier.from_string(partname.lower())
        p['id'] = did

        LOGGER.info("Parsing '%s'", did.string)

        # information about the core and architecture
        core = device_file.query('//Core')[0].text.replace('ARM ', '').lower()
        if core.endswith('m4') or core.endswith('m7'):
            core += 'f'
        if did["family"] in ['f7'] and did["name"] not in ['45', '46', '56']:
            core += 'd'
        p['core'] = core

        # flash and ram sizes
        # The <ram> and <flash> can occur multiple times.
        # they are "ordered" in the same way as the `(S-I-Z-E)` ids in the device combo name
        # we must first find out which index the current did["size"] has inside `(S-I-Z-E)`
        sizeIndexFlash = 0
        sizeIndexRam = 0

        match = re.search("\(.(-.)*\)", comboDeviceName)
        if match:
            sizeArray = match.group(0)[1:-1].lower().split("-")
            sizeIndexFlash = sizeArray.index(did["size"])
            sizeIndexRam = sizeIndexFlash

        rams = sorted([int(r.text) for r in device_file.query("//Ram")])
        if sizeIndexRam >= len(rams):
            sizeIndexRam = len(rams) - 1

        flashs = sorted([int(f.text) for f in device_file.query("//Flash")])
        if sizeIndexFlash >= len(flashs):
            sizeIndexFlash = len(flashs) - 1

        mem_start, mem_model = stm.getMemoryForDevice(did)
        total_ram = ram = rams[sizeIndexRam] * 1024 + mem_model['sram1']
        flash = flashs[sizeIndexFlash] * 1024 + mem_model['flash']
        if 'ccm' in mem_model:
            total_ram += mem_model['ccm']
        if 'backup' in mem_model:
            total_ram += mem_model['backup']
        if 'itcm' in mem_model:
            total_ram += mem_model['itcm']
            total_ram += mem_model['dtcm']
        p['ram'] = total_ram
        p['flash'] = flash

        # first get the real SRAM1 size
        for mem, val in mem_model.items():
            if any(s in mem for s in ['2', '3', 'dtcm']):
                ram -= val

        memories = []
        # add all memories
        for mem, val in mem_model.items():
            if '1' in mem:
                memories.append({'name': 'sram1',
                                 'access' : 'rwx',
                                 'start': "0x{:02X}".format(mem_start['sram' if 'sram' in mem_start else 'sram1']),
                                 'size': str(ram)})
            elif '2' in mem:
                memories.append({'name': 'sram2',
                                 'access' : 'rwx',
                                 'start': "0x{:02X}".format((mem_start['sram'] + ram) if 'sram' in mem_start else mem_start['sram2']),
                                 'size': str(val)})
            elif '3' in mem:
                memories.append({'name': 'sram3',
                                 'access': 'rwx',
                                 'start': "0x{:02X}".format(mem_start['sram'] + ram + mem_model['sram2']),
                                 'size': str(val)})
            elif 'flash' in mem:
                memories.append({'name': 'flash',
                                 'access': 'rx',
                                 'start': "0x{:02X}".format(mem_start['flash']),
                                 'size': str(flash)})
            else:
                memories.append({'name': mem,
                                 'access': 'rw' if did["family"] == 'f4' and mem == 'ccm' else 'rwx',
                                 'start': "0x{:02X}".format(mem_start[mem]),
                                 'size': str(val)})

        p['memories'] = memories

        # packaging
        package = device_file.query("//@Package")[0]
        p['pin-count'] = re.findall('[0-9]+', package)[0]
        p['package'] = re.findall('[A-Za-z\.]+', package)[0]

        # device defines
        defines = []
        cmsis_folder = os.path.join(STMDeviceTree.cmsis_headers, "stm32{}xx".format(did["family"]), "include")
        family_header = "stm32{}xx.h".format(did["family"])
        dev_def = None

        with open(os.path.join(cmsis_folder, family_header), 'r', errors="replace") as headerFile:
            match = re.findall("if defined\((?P<define>STM32[F|L].....)\)", headerFile.read())
            if match:
                dev_def = stm.getDefineForDevice(did, match)
        if dev_def is None:
            LOGGER.error("Define not found for device '{}'".format(did.string))
            return None

        p['cmsis_define'] = dev_def

        def clean_up_version(version):
            match = re.search("v[1-9]_[0-9x]", version.replace('.', '_'))
            if match:
                version = match.group(0).replace('_', '.')
            else:
                print(version)
            return version

        modules = []
        for ip in device_file.query("//IP"):
            # These IPs are all software modules, NOT hardware modules. Their version string is weird too.
            if ip.get('Name') in ['FATFS', 'TOUCHSENSING', 'PDM2PCM', 'MBEDTLS', 'FREERTOS', 'CORTEX_M7', 'NVIC', 'USB_DEVICE', 'USB_HOST', 'LWIP', 'LIBJPEG']:
                continue

            rversion = ip.get('Version')
            module = (ip.get('Name'), ip.get('InstanceName'), clean_up_version(rversion))

            if module[0] == 'DMA':
                # lets load additional information about the DMA
                dmaFile = XMLReader(os.path.join(STMDeviceTree.rootpath, 'IP', 'DMA-' + rversion + '_Modes.xml'))
                for dma in dmaFile.query("//IP/ModeLogicOperator/Mode[starts-with(@Name,'DMA')]/@Name"):
                    modules.append((module[0].lower(), dma.lower(), module[2].lower()))
                continue
            if module[0].startswith('TIM'):
                module = ('TIM',) + module[1:]

            modules.append(tuple([m.lower() for m in module]))

        modules = [m + stm_peripherals.getPeripheralData(did, m) for m in modules]

        p['modules'] = modules
        LOGGER.debug("Available Modules are:\n" + STMDeviceTree._modulesToString(modules))
        instances = [m[1] for m in modules]

        # add entire interrupt vectore table here.
        # I have not found a way to extract the correct vector _position_ from the ST device files
        # so we have to swallow our pride and just parse the header file
        headerFilePath = os.path.join(cmsis_folder, '{}.h'.format(dev_def.lower()))
        with open(headerFilePath, 'r', errors="replace") as headerFile:
            match = re.search("typedef enum.*?/\*\*.*?/\*\*.*?\*/(?P<table>.*?)} IRQn_Type;", headerFile.read(), re.DOTALL)
        if not match:
            LOGGER.error("Interrupt vector table not found for device '{}'".format(did.string))
            return None
        ivectors = []
        for line in match.group('table').split('\n')[1:-1]:
            if '=' not in line:  # avoid multiline comment
                continue

            name, pos = line.split('/*!<')[0].split('=')
            pos = int(pos.strip(' ,'))
            name = name.strip()[:-5]
            # What is this. I don't even.
            if did["family"] in ['f3'] and pos == 42 and name == 'USBWakeUp':
                continue
            ivectors.append({'position': pos, 'name': name})
        LOGGER.debug("Found interrupt vectors:\n" + "\n".join(["{}: {}".format(v['position'], v['name']) for v in ivectors]))
        p['interrupts'] = ivectors

        # lets load additional information about the GPIO IP
        ip_file = device_file.query("//IP[@Name='GPIO']")[0].get('Version')
        ip_file = os.path.join(STMDeviceTree.rootpath, 'IP', 'GPIO-' + ip_file + '_Modes.xml')
        gpioFile = XMLReader(ip_file)

        pins = device_file.query("//Pin[@Type='I/O'][starts-with(@Name,'P')]")
        pins = sorted(pins, key=lambda p: [p.get('Name')[1:2], int(p.get('Name')[:4].split('-')[0].split('/')[0][2:])])

        gpios = []
        remaps = {}

        # expand instance and channel information
        def snfn(name):
            nname = ""
            nnumber = ""
            for ch in name:
                if ch.isdigit():
                    nnumber += ch
                else:
                    nname += ch
            return (nname, int(nnumber) if len(nnumber) else None)

        def snfn2(driver, signal):
            if 'i2c' in driver or 'i2s' in driver:
                return (driver[:3], snfn(driver[2:])[1], signal)
            elif driver == 'tsc':
                return (driver, None, signal)
            elif driver.startswith('usb'):
                return ('usb', driver.replace('usb', '') if driver != 'usb' else None, signal)
            elif 'osc' in signal:
                return ('rcc', 'ls' if '32' in signal else 'hs', signal)
            return snfn(driver) + (signal,)

        def rename_af(af):
            # renames signals to fit better into our schema
            if af[0][0] == 'cec':
                af = (('hdmi_cec', 'cec'), af[1])
            if af[0][0] == 'ir':
                af = (('irtim',) + af[0][1:], af[1])
            if af[0][0] == 'eventout':
                af = (('sys', 'eventout'), af[1])
            if af[0][0] == 'sys' and '-' in af[0][1]:
                return [(('sys', v), af[1]) for v in af[0][1].split('-')]
            if af[0][0] == 'rcc' and 'mco' in af[0][1] and len(af[0]) > 2:
                af = (('rcc', 'mco', 'out' + af[0][2]), af[1])
            if af[0][0] == 'rcc' and 'osc' in af[0][1]:
                af = (('rcc' + 'ls' if '32' in af[0][1] else 'hs', af[0][2]), af[1])
            if af[0][0] == 'crs':
                af = (('usb',) + af[0], af[1])
            if af[0][0] == 'usb' and len(af[0]) > 3:
                af = (('usb' + af[0][2], af[0][-1]), af[1])
            if af[0][0] == 'rtc' and af[0][1] in ['out', 'in'] and len(af[0]) > 2:
                af = (('rtc', af[0][2], af[0][1]), af[1])
            if af[0][0].startswith('opamp') and len(af[0]) == 3:
                return []
            if (af[0][0].startswith('opamp') or af[0][0].startswith('comp')) and 'in' in af[0][1]:
                af = ((af[0][0], af[0][1][:-1], af[0][1][-1]), af[1])
            if af[0][0] == 'tsc' and len(af[0]) > 2:
                af = (('tsc', af[0][1], af[0][2][2:]), af[1])
            if len(af[0]) > 2:
                af = ((af[0][0], ''.join(af[0][1:])), af[1])
            return [af]

        if did['family'] == 'f1':
            grouped_f1_signals = gpioFile.compactQuery("//GPIO_Pin/PinSignal/@Name")

        for pin in pins:
            rname = pin.get('Name')
            name = rname[:4].split('-')[0].split('/')[0].strip()

            # the analog channels are only available in the Mcu file, not the GPIO file
            localSignals = device_file.compactQuery("//Pin[@Name='{}']/Signal[not(@Name='GPIO')]/@Name".format(rname))
            altFunctions = []

            if did['family'] == 'f1':
                altFunctions = [ (tuple(s.lower().split('_')), '-1') for s in localSignals if s not in grouped_f1_signals]
            else:
                allSignals = gpioFile.compactQuery("//GPIO_Pin[@Name='{}']/PinSignal/SpecificParameter[@Name='GPIO_AF']/..".format(rname))
                signalMap = { a.get('Name'): a[0][0].text.lower().replace('gpio_af', '')[:2].replace('_', '') for a in allSignals }
                altFunctions = [ (tuple(s.lower().split('_')), (signalMap[s] if s in signalMap else '-1')) for s in localSignals ]

            afs = []
            for af in altFunctions:
                straf = str(af)
                try:
                    naf = rename_af(af)
                except Exception as e:
                    print(straf, e)
                    exit(1)
                for saf in naf:
                    naf = {}
                    naf['driver'], naf['instance'], naf['name'] = snfn2(saf[0][0], saf[0][1])
                    naf['af'] = saf[1] if int(saf[1]) >= 0 else None
                    afs.append(naf)
                    # print(af, "->", saf, naf)

            gpio = (name[1:2].lower(), name[2:].lower(), afs)
            gpios.append(gpio)
            # print(gpio[0].upper(), gpio[1], afs)
            # LOGGER.debug("%s%s: %s ->", gpio[0].upper(), gpio[1])

        # exit(1)

        if did['family'] == 'f1':
            for remap in gpioFile.compactQuery("//GPIO_Pin/PinSignal/RemapBlock/@Name"):
                module = remap.split('_')[0].lower()
                config = remap.split('_')[1].replace('REMAP', '').replace('IREMAP', '')
                mapping = stm.getRemapForModuleConfig(module, config)

                mpins = []
                for pin in gpioFile.compactQuery("//GPIO_Pin/PinSignal/RemapBlock[@Name='{}']/..".format(remap)):
                    name = pin.getparent().get('Name')[:4].split('-')[0].split('/')[0].strip().lower()
                    pport, ppin = name[1:2], name[2:]
                    if not any([pp[0] == pport and pp[1] == ppin for pp in gpios]):
                        continue
                    mmm = {'port': pport, 'pin': ppin}
                    af = rename_af( (tuple(pin.get('Name').lower().split('_')), '-1') )[0]
                    _, _, mmm['name'] = snfn2(af[0][0], af[0][1])
                    mpins.append(mmm)

                if module not in remaps:
                    remaps[module] = {
                        'mask': mapping['mask'],
                        'position': mapping['position'],
                        'groups': {}
                    }
                    remaps[module]['driver'], remaps[module]['instance'], _ = snfn2(module, "")
                if len(mpins) > 0:
                    remaps[module]['groups'][mapping['mapping']] = mpins
                    LOGGER.debug("{:<20}{}".format(module + '_' + config, ["{}{}:{}".format(b['port'], b['pin'], b['name']) for b in mpins]))

            # import json
            # print(json.dumps(remaps, indent=4))

        p['remaps'] = remaps
        p['gpios'] = gpios

        return p

    @staticmethod
    def _modulesToString(modules):
        string = ""
        mods = sorted(modules)
        char = mods[0][0][0:1]
        for _, instance, _, _, _, _ in mods:
            if not instance.startswith(char):
                string += "\n"
            string += instance + " \t"
            char = instance[0][0:1]
        return string

    @staticmethod
    def _device_tree_from_properties(p):
        tree = DeviceTree('device')
        tree.ids.append(p['id'])
        LOGGER.info(("Generating Device Tree for '%s'" % p['id'].string))

        # def topLevelOrder(e):
        #     order = ['attribute-flash', 'attribute-ram', 'attribute-core', 'header', 'attribute-define']
        #     if e.name in order:
        #         if e.name in ['attribute-flash', 'attribute-ram']:
        #             return (order.index(e.name), int(e['value']))
        #         else:
        #             return (order.index(e.name), e['value'])
        #     return (len(order), -1)
        # tree.addSortKey(topLevelOrder)

        # STMDeviceTree.addDeviceAttributesToNode(p, tree, 'attribute-flash')
        # STMDeviceTree.addDeviceAttributesToNode(p, tree, 'attribute-ram')
        # STMDeviceTree.addDeviceAttributesToNode(p, tree, 'attribute-pin-count')

        def driverOrder(e):
            if e.name == 'driver':
                if e['name'] == 'core':
                    # place the core at the very beginning
                    return ('aaaaaaa', e['type'])
                if e['name'] == 'gpio':
                    # place the gpio at the very end
                    return ('zzzzzzz', e['type'])
                # sort remaining drivers by type and compatible strings
                return (e['name'], e['type'])
            return ("", "")
        tree.addSortKey(driverOrder)

        core_child = tree.addChild('driver')
        core_child.setAttributes('name', 'core', 'type', p['core'])
        # Memories
        STMDeviceTree.addMemoryToNode(p, core_child)
        STMDeviceTree.addInterruptTableToNode(p, core_child)

        modules = {}
        for m, i, _, h, f, pr in p['modules']:
            # if m in ['fatfs', 'freertos']: continue;
            if m+h not in modules:
                modules[m+h] = (m, h, f, pr, [i])
            else:
                if (modules[m+h][1] != h):
                    print(modules[m+h], '<-', (m, h, f, pr, i))
                modules[m+h][4].append(i)

        # add all other modules
        gpio_version = 'stm32'
        for name, hardware, features, protocols, instances in modules.values():
            if name == 'gpio':
                gpio_version = hardware
                continue

            driver = tree.addChild('driver')
            driver.setAttributes('name', name, 'type', hardware)
            def driver_sort_key(e):
                if e.name == 'feature':
                    return (0, 0, e['value'])
                return (1, int(e['value']), "")
            driver.addSortKey(driver_sort_key)
            for f in features:
                feat = driver.addChild('feature')
                feat.setValue(f)
            # for pr in protocols:
            #     prot = driver.addChild('protocol')
            #     prot.setValue(pr)
            # Add all instances to this driver
            if any(i != name for i in instances):
                for i in instances:
                    inst = driver.addChild('instance')
                    inst.setValue(i[len(name):])

        # GPIO driver
        gpio_driver = tree.addChild('driver')
        gpio_driver.setAttributes('name', 'gpio', 'type', gpio_version)

        if p['id']['family'] == 'f1':
            # Add the remap group tree
            for remap in p['remaps'].values():
                if len(remap['groups']) == 0: continue;
                remap_ch = gpio_driver.addChild('remap')
                remap_ch.setAttributes(['driver'], remap)
                if remap['instance'] is not None:
                    remap_ch.setAttributes(['instance'], remap)
                remap_ch.setAttributes(['position', 'mask'], remap)
                remap_ch.addSortKey(lambda e: int(e['id']))

                for group, pins in remap['groups'].items():
                    group_ch = remap_ch.addChild('group')
                    group_ch.setAttributes('id', group)
                    group_ch.addSortKey(lambda e : (e['port'], int(e['pin']), e['name']))

                    for pin in pins:
                        pin_ch = group_ch.addChild('signal')
                        pin_ch.setAttributes(['port', 'pin', 'name'], pin)

        # Sort these things
        def sort_gpios(e):
            if e['driver'] is None:
                return (100, "", 0, e['port'], int(e['pin']))
            else:
                return (int(e['position']), e['driver'], int(0 if e['instance'] is None else e['instance']), "", 0)
        gpio_driver.addSortKey(sort_gpios)

        for port, pin, signals in p['gpios']:
            pin_driver = gpio_driver.addChild('gpio')
            pin_driver.setAttributes('port', port, 'pin', pin)
            pin_driver.addSortKey(lambda e: (int(e['af']) if e['af'] is not None else -1,
                                             e['driver'],
                                             e['instance'] if e['instance'] is not None else '',
                                             e['name']))
            # add all signals
            for s in signals:
                afid, driver, instance, name = s['af'], s['driver'], s['instance'], s['name']
                # if driver.startswith('tc'): driver = 'tc';
                # if driver == 'cpu': driver = 'core'; instance = 'core';
                # add the af node
                af = pin_driver.addChild('signal')
                if afid is not None and afid != '':
                    af.setAttributes('af', afid)
                af.setAttributes('driver', driver)
                if instance is not None:
                    af.setAttributes('instance', instance)
                af.setAttributes('name', name)

        return tree


    @staticmethod
    def addDeviceAttributesToNode(p, node, name):
        pname = name.split('-')[-1]
        props = p[pname]
        if not isinstance(props, list):
            props = [props]
        for prop in props:
            child = node.addChild(name)
            child.setAttribute('value', prop)
            child.setIdentifier(lambda e: e.name)

    @staticmethod
    def addMemoryToNode(p, node):
        for section in p['memories']:
            memory_section = node.addChild('memory')
            memory_section.setAttributes(['name', 'access', 'start', 'size'], section)
            memory_section.setIdentifier(lambda e: e['name'])
        # sort the node children by start address and size
        node.addSortKey(lambda e: (int(e['start'], 16), int(e['size'])) if e.name == 'memory' else (-1, -1))

    @staticmethod
    def addInterruptTableToNode(p, node):
        interrupts = p['interrupts']

        for vector in interrupts:
            vector_section = node.addChild('vector')
            vector_section.setAttributes(['position', 'name'], vector)
            vector_section.setIdentifier(lambda e: e['position'])
        # sort the node children by vector number and name
        node.addSortKey(lambda e: (int(e['position']), e['name']) if e.name == 'vector' else (-1, ""))

    @staticmethod
    def addModuleAttributesToNode(p, node, peripheral, name, family='stm32'):
        modules = p['modules']

        peripherals = []
        if isinstance(peripheral, list):
            peripherals.extend(peripheral)
        else:
            peripherals.append(peripheral)

        driver = node.addChild('driver')
        driver.setAttributes('name', name, 'type', family)
        driver.addSortKey(lambda e: int(e['value']))
        driver.setIdentifier(lambda e: e['name'] + e['hw'])

        for module in modules:
            instances = []
            found = False
            for p in peripherals:
                if module.startswith(p):
                    found = True
                    inst = module[len(p):]
                    if inst != '' and inst.isdigit():
                        instances.append(inst)

            if not found:
                continue
            for instance in instances:
                child = driver.addChild('instance')
                child.setAttribute('value', instance)
                child.setIdentifier(lambda e: e.name)

    @staticmethod
    def from_partname(partname):
        p = STMDeviceTree._properties_from_partname(partname)
        if p is None: return None;
        return STMDeviceTree._device_tree_from_properties(p)
