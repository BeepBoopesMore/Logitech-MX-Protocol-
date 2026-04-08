import ctypes
from bleak import BleakScanner
import asyncio
from bleak import BleakClient
from enum import auto
from enum import Enum
from typing import List
import subprocess

class Action(Enum):
    SCROLL_UP = auto()   # 0x0f 00 01 ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00
    SCROLL_DOWN = auto() #    #0x0f 0x00 0x01 0x00 0x01 0x00 00 00 00 00 00 00 00 00 00 00 00 00 - Mouse scroll wheel
    UNDEFINED = auto()
    CLICK_LEFT = auto()
    CLICK_LEFT_CONFIRMATION = auto()
    CLICK_RIGHT = auto()
    CLICK_RIGHT_CONFIRMATION = auto()
    HID = auto()
 

""""


00 0c 02 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 1c 04 05 1d 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 0c 01 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
01 0c 24 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 1
00 1c 04 05 84 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 0c 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
12 0c 00 00 1e 01 00 00 00 00 00 00 00 00 00 00 00 00 Action: 18
00 1c 04 05 b0 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 0c 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
03 2c 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 3
03 0c 0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 3
03 1c 4d 58 20 4d 61 73 74 65 72 20 33 53 00 00 00 00 Action: 3
00 1c 04 05 86 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 1c 04 05 96 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 1c 04 05 5f 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 1c 04 05 b7 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
12 0c 00 00 1e 01 00 00 00 00 00 00 00 00 00 00 00 00 Action: 18
12 0c 00 00 1e 01 00 00 00 00 00 00 00 00 00 00 00 00 Action: 18
00 1c 04 05 bc 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 1c 04 05 52 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 1c 04 05 71 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 0c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 1c 04 05 df 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0
00 0c 09 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 Action: 0

Some part of the boot section , this is what mostly needs to be checked 
"""



# Basically a reverse engineer of the logitech protocol 
# We will use the /dev/ ioctl 
def hook_libc():
    pass

# Logitech uses some mechanism to check if the mouse is actually doing events , we need to find which that is 
# The callback we call to send the data back 
def callback(sender,data):
    import struct
    c = bytes(data)
    # This is the scroll wheel event 
    if c[0] == 0x0F:
        direction = struct.unpack("<h",data[2:4])[0]
        value = Action.SCROLL_UP if direction > 0 else Action.SCROLL_DOWN
    # This is the click event 
    elif c[0] == 0x9: # Logitech uses a confirmation packet after
        print("Found a mouse click",c.hex(sep=' '))
    elif c[0] == 0x02: # Connecting status?? HID ++ 
        value = Action.HID





    else:
        print(c.hex(sep=' '),"Action: %d" %c[0])

    





 
async def find_uuid():
    devices =  await BleakScanner.discover()
    for device in devices:
        if device.name is None:
            continue
        if device.name.startswith("MX"):
            a = device.address
    
    async with BleakClient(a) as client:
        d = client.services
        for service in d:
            for c in service.characteristics:
                print("UUID: %s Property %s Description %s"%c.uuid,c.properties,c.description)

async def scan():
    devices = await BleakScanner.discover()


    # Getting the mac address 
    for device in devices:
        if device.name is None:
            continue
    
        if device.name.startswith("MX"):
            a = device.address 




    UUID    = "00010001-0000-1000-8000-011f2000046d" # Main , this takes the packets , etc. 
    UUID_1 = "00002a29-0000-1000-8000-00805f9b34fb"  # Property: ['read'] This is broken 
    UUID_2 = "00002a24-0000-1000-8000-00805f9b34fb"  # Property: ['read']
    UUID_3 = "00002a25-0000-1000-8000-00805f9b34fb"  # Property: ['read']
    UUID_4 = "00002a26-0000-1000-8000-00805f9b34fb"  # Property: ['read']
    UUID_5 = "0002a28-0000-1000-8000-00805f9b34fb"  # Property: ['read']
    UUID_6 = "00002a50-0000-1000-8000-00805f 9b34fb"  # Property: ['read']
    UUID_7 = "00002a19-0000-1000-8000-00805f9b34fb"  # Property: ['notify', 'read']
    UUID_FD1 = "fd720001-0000-1000-8000-011f2000046d"  # Property: ['read']
    UUID_FD2 = "fd720002-0000-1000-8000-011f2000046d"  # Property: ['read']
    UUID_FD3 = "fd720003-0000-1000-8000-011f2000046d"  # Property: ['write']
    UUID_FD4 = "fd720004-0000-1000-8000-011f2000046d"  # Property: ['read']
    UUID_FD5 = "fd720005-0000-1000-8000-011f2000046d"  # Property: ['read']
    UUID_FD6 = "fd720006-0000-1000-8000-011f2000046d"  # Property: ['write']

    # Start using the uuids
    async with BleakClient(a) as client:
            await client.start_notify(UUID,callback=callback) 
            print("Hearing the packets... yummy")
            await asyncio.sleep(60)
            print("**Done sending the data***")
            subprocess.run(["sudo","pkill","bluetoothd"])




asyncio.run(scan())








