import ctypes
from bleak import BleakScanner
import asyncio
from bleak import BleakClient
import struct



# Basically a reverse engineer of the logitech protocol 
# We will use the /dev/ ioctl 
def hook_libc():
    pass



# The callback we call to send the data back 
def callback(sender,data):
    c = bytes(data)
    print(c.hex(sep=' '))



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


    #0f 00 01 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 - Mouse scroll wheel


    UUID    = "00010001-0000-1000-8000-011f2000046d" # Main , this takes the packets , etc. 
    UUID_1 = "00002a29-0000-1000-8000-00805f9b34fb"  # Property: ['read'] This is broken 
    UUID_2 = "00002a24-0000-1000-8000-00805f9b34fb"  # Property: ['read']
    UUID_3 = "00002a25-0000-1000-8000-00805f9b34fb"  # Property: ['read']
    UUID_4 = "00002a26-0000-1000-8000-00805f9b34fb"  # Property: ['read']
    UUID_5 = "0002a28-0000-1000-8000-00805f9b34fb"  # Property: ['read']
    UUID_6 = "00002a50-0000-1000-8000-00805f9b34fb"  # Property: ['read']
    UUID_7 = "00002a19-0000-1000-8000-00805f9b34fb"  # Property: ['notify', 'read']
    UUID_FD1 = "fd720001-0000-1000-8000-011f2000046d"  # Property: ['read']
    UUID_FD2 = "fd720002-0000-1000-8000-011f2000046d"  # Property: ['read']
    UUID_FD3 = "fd720003-0000-1000-8000-011f2000046d"  # Property: ['write']
    UUID_FD4 = "fd720004-0000-1000-8000-011f2000046d"  # Property: ['read']
    UUID_FD5 = "fd720005-0000-1000-8000-011f2000046d"  # Property: ['read']
    UUID_FD6 = "fd720006-0000-1000-8000-011f2000046d"  # Property: ['write']


    async with BleakClient(a) as client:
        await client.start_notify(UUID,callback=callback)
        print("Hearing the packets... yummy")
        await asyncio.sleep(60)

        print("**Done sending the data***")

            

    




asyncio.run(scan())





