# cybersecurity-course
This project is for save the script that I have to make for the cyber security course in Fundación Telefónica

Before execute evaluacionPython.py you have to install this tools:

1. <a href="https://pypi.org/project/netifaces/" target="_blank">netifaces</a>
2. <a href="https://pypi.org/project/python-nmap/" target="_blank">nmap</a>
3. <a href="https://pypi.org/project/requests/" target="_blank">requests</a>

Then open your terminal and write the command: `python evaluacionPython.py -i your_adapter`
e.g: `python evaluacionPython.py -i eth0`

Output:
```
Buscando maquinas en la red: xxx.xxx.xxx.xxx/xx
===============================================================
IP: xxx.xxx.xxx.xxx
Estado: up
-------------
Protocolo: tcp
Puerto: 111 - cerrado
-------------
Protocolo: udp
Puerto: 3306 - 5.5.5-10.4.6-MariaDB


################################################
Enviando datos al sitio http://127.0.0.1/example/fake_url.php
```
