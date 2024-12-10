sudo rm networks.temp* > /dev/null
rm -f  basic_wep.cap-0* > /dev/null
sudo airmon-ng stop $1 > /dev/null
sudo systemctl start NetworkManager > /dev/null