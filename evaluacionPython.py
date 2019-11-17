import netifaces
import sys
import nmap
import socket
import json
import requests
 
def getBitsNetmask(netmask):
    return sum([bin(int(x)).count("1") for x in netmask.split(".")])
 
def scanBanner(ip,port):
    try:   
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        s.send(b'200 OK\r\n')
        banner = s.recv(1024).decode("utf-8", "ignore")
       
        print("Puerto: " + str(port) + " - " + banner)
    except socket.error as e:
        if 'timed out' in str(e):
            banner = "filtrado"
        else:
            banner = "cerrado"
       
        print("Puerto: " + str(port) + " - "+ banner)
    finally:
        s.close()
        return banner
 
def saveToFile(data):
    with open('output.json', 'w') as outfile:
        json.dump(data, outfile, ensure_ascii=False, indent=4)
 
def postToPage(data_json):
    try:
        url_post = "http://127.0.0.1/example/fake_url.php"
        print("###########################################")
        print("Enviando datos al sitio %s" % (url_post))
        req = requests.post(url_post, json=data_json)
        status_code = req.status_code
        if (status_code == 404):
            print("la pagina no responde")
        elif (status_code == 200):
            print("Todo OK!")
        else:
            print("Otro Error")
    except:
        print("ocurrio un error, no se pudo realizar el post al sitio")
 
list_output = []
 
try:
    if len(sys.argv) != 3:
        raise Exception("Ejecucion incorrecta, vuelva a intentarlo, agregue en el comando -i interfaz, ejemplo -i eth0")   
   
    interfaz = sys.argv[2]
    addrs = netifaces.ifaddresses(interfaz)
    IP_RANGE = str(addrs[netifaces.AF_INET][0]['addr']) + "/" + str(getBitsNetmask(addrs[netifaces.AF_INET][0]['netmask']))
    print("Buscando maquinas en la red: " + IP_RANGE)
    nm = nmap.PortScanner()
    nm.scan(IP_RANGE, arguments='-sU -sT')
 
    for host in nm.all_hosts():
        print("==========================================================")
        print("IP: %s (%s)" % (host, nm[host].hostname()))
        print("Estado : %s" % nm[host].state())
        item = {
        "IP": host,
        "ESTADO": nm[host].state(),
        "TCP": [],
        "UDP": []}
 
        for proto in nm[host].all_protocols():
            print("----------")
            print("Protocolo : %s" % proto)
            lport = nm[host][proto].keys()
            for port in lport:
                if (proto == "tcp"):
                    item["TCP"].append({
                    "puerto": port,
                    "banner": scanBanner(host, port)
                })
                else:
                    item["UDP"].append({
                        "puerto": port,
                        "banner": scanBanner(host, port)
                    })
        # for by proto
        list_output.append(item)
    # for by host
    saveToFile(list_output)
    postToPage(list_output)
 
except Exception as e:
    print(e)
    exit()