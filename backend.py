import numpy as np
import pandas as pd
import subprocess
import multiprocessing
import asyncio
import time

# State
currentMonitorAdapter = "_no_adapter_"
isPollingNetworks = False
isDumpingNetword = False

# Const
framesNeeded = 15000

def checkMonitorAdapter():
    return currentMonitorAdapter != "_no_adapter_"

def main():
    try:
        adapters = GetAdapters()
        SwitchMonitorMode(adapters[0])
        StartWepNetworksSearching()
        time.sleep(100)
    finally:
        subprocess.run(["bash", "clean.sh", currentMonitorAdapter])
        return

# return exit code of child process
def Prepare() -> int:
    ok = subprocess.run(["sudo", "airmon-ng", "check", "kill"])
    return ok

def GetAdapters():
    subprocess.run(["bash", "GetAdapters.sh"])
    adaptersDf = pd.read_csv('adapters.txt', sep='\t')
    adapters = list(adaptersDf['Interface'])
    subprocess.run(['rm', 'adapters.txt'])

    return adapters

def SwitchMonitorMode(adapter : str):
    ok = subprocess.run(["sudo", "airmon-ng", "start", adapter])
    if ok:
        global currentMonitorAdapter
        currentMonitorAdapter = adapter + "mon"
    return ok

def StartWepNetworksSearching():
    if checkMonitorAdapter():
        process = subprocess.Popen(["sudo", "airodump-ng", currentMonitorAdapter, "--encrypt", "WEP", "-o", "csv", "-w", "networks.temp"])
        global isPollingNetworks
        isPollingNetworks = True
        return process
    return 0

def StopWepNetworksSearching(process : subprocess.Popen):
    global isPollingNetworks
    isPollingNetworks = False

    process.terminate()
    process.wait()
    subprocess.run(['rm', 'networks.temp*'])
    return # list of dictionaries of network name, network bssid, network channel

def GetWepNetworks():
    if (checkMonitorAdapter()):
        networksDf = pd.read_csv('networks.temp', sep='\t')
        # return list of dictionaries with network name, BSSID and Channel
        return []
    return []

def StartNetworkDumping(network):
    process = subprocess.Popen(["sudo", "airodump-ng", "-bssid", network['BSSID'], "--channel", network['CH'], "--write", "basic_wep.cap", currentMonitorAdapter])
    return process

def GetFramesQuantity() -> int:
    # 
    return 0

def GetNetworkKey():
    return

def RemoveTempFiles():
    return

def BackendShutdown():
    return




if __name__ == '__main__':
    main()