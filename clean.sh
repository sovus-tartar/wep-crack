# removing temp files
rm -f networks.temp* > /dev/null
rm -f basic_wep.cap-0* > /dev/null
rm -f key.log > /dev/null

# disabling monitor mode
sudo airmon-ng stop $1 > /dev/null
