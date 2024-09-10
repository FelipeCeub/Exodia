#!/usr/bin/env python3
#imports
import os
from hashid import HashID
import re
import nmap
import hashlib
import time
import subprocess
import webbrowser


#Exodia Menu
def mExodia():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
███████╗██╗  ██╗ ██████╗ ██████╗ ██╗ █████╗ 
██╔════╝╚██╗██╔╝██╔═══██╗██╔══██╗██║██╔══██╗
█████╗   ╚███╔╝ ██║   ██║██║  ██║██║███████║
██╔══╝   ██╔██╗ ██║   ██║██║  ██║██║██╔══██║
███████╗██╔╝ ██╗╚██████╔╝██████╔╝██║██║  ██║
╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═╝
____________________________________________
''')
        print('[1]𝐓𝐨𝐨𝐥𝐬\n[2]𝐀𝐫𝐬𝐞𝐧𝐚𝐥\n[X]𝐄𝐱𝐢𝐭')
        try:
            choose = str(input('>>> '))
        except ValueError:
            continue
        if choose == "1":
            mTools()
            break
        elif choose == "2":
            mArsenal()
            break
        elif choose == 'x':
            print('𝑩𝒚𝒆 𝑩𝒚𝒆...')
            break

#Tools Menu
def mTools():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
              
░▀█▀░█▀█░█▀█░█░░░█▀▀
░░█░░█░█░█░█░█░░░▀▀█
░░▀░░▀▀▀░▀▀▀░▀▀▀░▀▀▀
____________________
''')
        print('[1]Wordlists\n[2]Scan\n[3]Cryptography\n[X]Back')
        try:
            choose = str(input('>>> '))
        except ValueError:
            continue
        if choose == "1":
            mWordlists()
            break
        elif choose == "2":
            mScan()
        elif choose == "3":
            mCryptography()
            break
        elif choose == 'x':
            mExodia()
            break

#Wordlists Menu
def mWordlists():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
              
░█░█░█▀█░█▀▄░█▀▄░█░░░▀█▀░█▀▀░▀█▀░█▀▀
░█▄█░█░█░█▀▄░█░█░█░░░░█░░▀▀█░░█░░▀▀█
░▀░▀░▀▀▀░▀░▀░▀▀░░▀▀▀░▀▀▀░▀▀▀░░▀░░▀▀▀
____________________________________
''')
        print('[1]Subdomain\n[2]Pass Crack\n[X]Back')
        try:
            choose = str(input('>>> '))
        except ValueError:
            continue
        if choose == "1":
            optSubdomain()
            break
        elif choose == "2":
            optPassCrack()
            break
        elif choose == 'x':
            mTools()
            break

#Subdomain options
def optSubdomain():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
              
░█▀▀░█░█░█▀▄░█▀▄░█▀█░█▄█░█▀█░▀█▀░█▀█
░▀▀█░█░█░█▀▄░█░█░█░█░█░█░█▀█░░█░░█░█
░▀▀▀░▀▀▀░▀▀░░▀▀░░▀▀▀░▀░▀░▀░▀░▀▀▀░▀░▀
____________________________________
''')
        print('[1]Dsplusleakypaths.txt\n[2]Common.txt\n[X]Back')
        try:
            choose = str(input('>>> '))
        except ValueError:
            continue
        if choose == "1":
            result = os.system('curl -O https://raw.githubusercontent.com/aels/subdirectories-discover/main/dsplusleakypaths.txt')
            input('Download Concluido')
        elif choose == "2":
            esult = os.system('curl -O https://raw.githubusercontent.com/v0re/dirb/blob/master/wordlists/common.txt')
            input('Download Concluido')
        elif choose == 'x':
            mWordlists()
            break

#PassCrack Options
def optPassCrack():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
              
░█░█░█▀█░█▀█░█▀▀░█▀▀░░░█▀▀░█▀▄░█▀█░█▀▀░█░█
░█▄█░█▀▀░█▀█░▀▀█░▀▀█░░░█░░░█▀▄░█▀█░█░░░█▀▄
░▀░▀░▀░░░▀░▀░▀▀▀░▀▀▀░░░▀▀▀░▀░▀░▀░▀░▀▀▀░▀░▀
__________________________________________
''')
        print('[1]RockYou.txt (Somente Linux)\n[X]Back')
        try:
            choose = str(input('>>> '))
        except ValueError:
            continue
        if choose == "1":
            user = os.getenv('USER')  # Obtém o nome do usuário atual
            desktop_dir = os.path.join('/home', user, 'Desktop')
            os.system(f'sudo cp -rf /usr/share/wordlists/rockyou.txt.tar.gz {desktop_dir}')
            input(f'Wordlist colada na pasta /home/{user}/Desktop')
        elif choose == 'x':
            mWordlists()
            break

#Scan Menu
def mScan():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
              
░█▀▀░█▀▀░█▀█░█▀█
░▀▀█░█░░░█▀█░█░█
░▀▀▀░▀▀▀░▀░▀░▀░▀
________________
''')
        print('[1]Port Scan\n[2]Device Scan\n[X]Back')
        try:
            choose = str(input('>>> '))
        except ValueError:
            continue
        if choose == "1":
            PortScan()
            break
        elif choose == "2":
            DeviceScan()
            break
        elif choose == 'x':
            mTools()
            break


#Port Scan
def PortScan():
    import nmap
    nm = nmap.PortScanner()
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
              
░█▀█░█▀█░█▀▄░▀█▀░░░█▀▀░█▀▀░█▀█░█▀█
░█▀▀░█░█░█▀▄░░█░░░░▀▀█░█░░░█▀█░█░█
░▀░░░▀▀▀░▀░▀░░▀░░░░▀▀▀░▀▀▀░▀░▀░▀░▀
__________________________________
''')
        target = input('Digite o endereço IP ou hostname para escanear: ')
        if not target:
            print("Nenhum endereço fornecido. Saindo.")
            break
        
        try:
            print("Iniciando o escaneamento...")
            nm.scan(hosts=target, arguments='-T5 -F -sV')  # -sV para detectar versões de serviços
            
            print("\nResultados do escaneamento:")
            for host in nm.all_hosts():
                print(f'\nHost: {host} ({nm[host].hostname()})')
                print(f'State: {nm[host].state()}')
                for proto in nm[host].all_protocols():
                    print('----------')
                    print(f'Protocol: {proto}')
                    lport = nm[host][proto].keys()
                    for port in sorted(lport):
                        if nm[host][proto][port]['state'] == 'open':
                            service = nm[host][proto][port]
                            print(f'Port: {port}\tService: {service["name"]}\tVersion: {service.get("product", "unknown")} {service.get("version", "")}')

                        
        except Exception as e:
            print(f"Erro ao realizar o escaneamento: {e}")
        
        input('\nPressione Enter para continuar...')
        break




#Device Scan
def DeviceScan():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
              
░█▀▄░█▀▀░█░█░▀█▀░█▀▀░█▀▀░░░█▀▀░█▀▀░█▀█░█▀█
░█░█░█▀▀░▀▄▀░░█░░█░░░█▀▀░░░▀▀█░█░░░█▀█░█░█
░▀▀░░▀▀▀░░▀░░▀▀▀░▀▀▀░▀▀▀░░░▀▀▀░▀▀▀░▀░▀░▀░▀
__________________________________________
''')
        input('Ainda to criando...')

#Cryptography Menu
def mCryptography():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
              
░█▀▀░█▀▄░█░█░█▀█░▀█▀░█▀█░█▀▀░█▀▄░█▀█░█▀█░█░█░█░█
░█░░░█▀▄░░█░░█▀▀░░█░░█░█░█░█░█▀▄░█▀█░█▀▀░█▀█░░█░
░▀▀▀░▀░▀░░▀░░▀░░░░▀░░▀▀▀░▀▀▀░▀░▀░▀░▀░▀░░░▀░▀░░▀░
________________________________________________
''')
        print('[1]Hash Identifier\n[2]Encrypt\n[3]Decrypt\n[X]Back')
        try:
            choose = str(input('>>> '))
        except ValueError:
            continue
        if choose == "1":
            HashIDF()
            break
        elif choose == "2":
            Encrypt()
            break
        elif choose == "3":
            Decrypt()
            break
        elif choose == 'x':
            mTools()
            break

#Hash Identifier
def identify_hash(hash_string):
    # Definir padrões para tipos de hash
    hash_types = {
        'MD5': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE),
        'SHA-1': re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE),
        'SHA-256': re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE),
        'SHA-512': re.compile(r'^[a-f0-9]{128}$', re.IGNORECASE),
    }
    
    # Tentar identificar o tipo de hash
    for hash_type, pattern in hash_types.items():
        if pattern.match(hash_string):
            return f'O tipo de hash é: {hash_type}'
    
    return 'Tipo de hash desconhecido'

def HashIDF():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
              
░█░█░█▀█░█▀▀░█░█░░░▀█▀░█▀▄
░█▀█░█▀█░▀▀█░█▀█░░░░█░░█░█
░▀░▀░▀░▀░▀▀▀░▀░▀░░░▀▀▀░▀▀░
__________________________           
''')
        hash_input = input("Digite a hash: ")
        print(identify_hash(hash_input))
        input("Pressione Enter para continuar...")
        mCryptography()
        break

#Encrypt Menu
def encrypt_string(algorithm, input_string):
    if algorithm == "MD5":
        return hashlib.md5(input_string.encode()).hexdigest()
    elif algorithm == "SHA-1":
        return hashlib.sha1(input_string.encode()).hexdigest()
    elif algorithm == "SHA-256":
        return hashlib.sha256(input_string.encode()).hexdigest()
    elif algorithm == "SHA-512":
        return hashlib.sha512(input_string.encode()).hexdigest()

def Encrypt():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
              
░█▀▀░█▀█░█▀▀░█▀▄░█░█░█▀█░▀█▀
░█▀▀░█░█░█░░░█▀▄░░█░░█▀▀░░█░
░▀▀▀░▀░▀░▀▀▀░▀░▀░░▀░░▀░░░░▀░
____________________________
''')
        print('[1]MD5\n[2]SHA-1\n[3]SHA-256\n[4]SHA-512\n[X]Back')
        try:
            choose = str(input('>>> ')).upper()
        except ValueError:
            continue
        if choose == "1":
            algorithm = "MD5"
        elif choose == "2":
            algorithm = "SHA-1"
        elif choose == "3":
            algorithm = "SHA-256"
        elif choose == "4":
            algorithm = "SHA-512"
        elif choose == 'X':
            mCryptography()
            break
        else:
            continue
        
        input_string = input(f"Digite a string para criptografar usando {algorithm}: ")
        encrypted_string = encrypt_string(algorithm, input_string)
        print(f"O resultado da criptografia {algorithm} é: {encrypted_string}")
        input("Pressione Enter para continuar...")

def Decrypt():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
              
░█▀▄░█▀▀░█▀▀░█▀▄░█░█░█▀█░▀█▀
░█░█░█▀▀░█░░░█▀▄░░█░░█▀▀░░█░
░▀▀░░▀▀▀░▀▀▀░▀░▀░░▀░░▀░░░░▀░
____________________________
''')
        print('Opções:\n[1]MD5\n[2]SHA-1\n[3]SHA-256\n[4]SHA-516\n[x]Back')
        choose = str(input('>>>'))
        import webbrowser

        if choose == "1":
            webbrowser.open("https://crackstation.net/")
            mCryptography()
            break
        elif choose == "2":
            webbrowser.open("https://crackstation.net/")
            mCryptography()
            break
        elif choose == "3":
            webbrowser.open("https://crackstation.net/")
            mCryptography()
            break
        elif choose == "4":
            webbrowser.open("https://crackstation.net/")
            mCryptography()
            break
        elif choose == "x":
            mCryptography()
            break

#Arsenal Menu
def mArsenal():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
░█▀█░█▀▄░█▀▀░█▀▀░█▀█░█▀█░█░░
░█▀█░█▀▄░▀▀█░█▀▀░█░█░█▀█░█░░
░▀░▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀░▀░▀▀▀
____________________________
''')
        print("𝐎𝐩𝐜̧𝐨̃𝐞𝐬:\n[𝟏]𝐎𝐟𝐞𝐧𝐬𝐢𝐯𝐞\n[𝟐]𝐃𝐞𝐟𝐞𝐧𝐬𝐢𝐯𝐞\n[𝐱]𝐁𝐚𝐜𝐤")
        try:
            choose = str(input('>>> '))
        except ValueError:
         continue
        if choose == "1":
            mOfensive()
            break
        elif choose == "2":
            mDefensive()
            break
        elif choose == 'x':
            mExodia()
            break

#Arsenal Menu
def mOfensive():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('''
░█▀█░█▀▀░█▀▀░█▀█░█▀▀░▀█▀░█░█░█▀▀
░█░█░█▀▀░█▀▀░█░█░▀▀█░░█░░▀▄▀░█▀▀
░▀▀▀░▀░░░▀▀▀░▀░▀░▀▀▀░▀▀▀░░▀░░▀▀▀
________________________________
''')
        print("𝐎𝐩𝐜̧𝐨̃𝐞𝐬:\n[𝟏]SQL Injection\n[𝟐]DDoS\n[3]Dawn Wifi\n[4]KeyLogger\n[𝐱]𝐁𝐚𝐜𝐤")
        try:
            choose = str(input('>>> '))
        except ValueError:
         continue
        if choose == "1":
            SQLInjection()
            break
        elif choose == "2":
            DDoS()
            break
        elif choose == "3":
            DawnWifi()
            break
        elif choose == "2":
            Keylogger()
            break
        elif choose == 'x':
            mArsenal()
            break

#Functions Ofensive
def SQLInjection():
    while True:
        os.system()
def mDefensive():
    while True:
        os.system('cls' if os.name == 'nt'else 'clear')
        print('''
░█▀▄░█▀▀░█▀▀░█▀▀░█▀█░█▀▀░▀█▀░█░█░█▀▀
░█░█░█▀▀░█▀▀░█▀▀░█░█░▀▀█░░█░░▀▄▀░█▀▀
░▀▀░░▀▀▀░▀░░░▀▀▀░▀░▀░▀▀▀░▀▀▀░░▀░░▀▀▀
____________________________________
''')
        print('Opções:\n[1]Anonymate\n[2]Malware Scan\n[x]Back')
        try:
            choose = str(input('>>> '))
        except ValueError:
            continue
        if choose == "1":
            mAnonymate()
            break
        elif choose == "2":
            MalwareScan
            break
        elif choose == "x":
            mArsenal()
            break

def mAnonymate():
    while True:
        os.system('cls' if os.name == 'nt'else 'clear')
        print('''
░█▀█░█▀█░█▀█░█▀█░█░█░█▄█░█▀█░▀█▀░█▀▀
░█▀█░█░█░█░█░█░█░░█░░█░█░█▀█░░█░░█▀▀
░▀░▀░▀░▀░▀▀▀░▀░▀░░▀░░▀░▀░▀░▀░░▀░░▀▀▀
____________________________________
''')
        print('Opções:\n[1]VPN\n[2]Auto Tor\n[x]Back')
        try:
            choose = str(input('>>> '))
        except ValueError:
            continue
        if choose == "1":
            VPN()
            break
        elif choose == "2":
            AutoTor()
            break
        elif choose == "x":
            mDefensive()
            break

def MalwareScan():
    while True:
        os.system('cls' if os.name == "nt" else "clear")
        print('''
░█▄█░█▀█░█░░░█░█░█▀█░█▀▄░█▀▀░░░█▀▀░█▀▀░█▀█░█▀█
░█░█░█▀█░█░░░█▄█░█▀█░█▀▄░█▀▀░░░▀▀█░█░░░█▀█░█░█
░▀░▀░▀░▀░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀░░░▀▀▀░▀▀▀░▀░▀░▀░▀
''')
        print("implementando")
        break
        
def AutoTor():
    while True:
        os.system('cls' if os.name == "nt" else "clear")
        try:
            check_pip3 = subprocess.check_output('dpkg -s python3-pip', shell=True)
            if str('install ok installed') in str(check_pip3):
                pass
        except subprocess.CalledProcessError:
            print('[+] pip3 not installed')
            subprocess.check_output('sudo apt update',shell=True)
            subprocess.check_output('sudo apt install python3-pip -y', shell=True)
            print('[!] pip3 installed succesfully')

        try:

            import requests
        except Exception:
            print('[+] python3 requests is not installed')
            os.system('pip3 install requests')
            os.system('pip3 install requests[socks]')
            print('[!] python3 requests is installed ')
        try:

            check_tor = subprocess.check_output('which tor', shell=True)
        except subprocess.CalledProcessError:

            print('[+] tor is not installed !')
            subprocess.check_output('sudo apt update',shell=True)
            subprocess.check_output('sudo apt install tor -y',shell=True)
            print('[!] tor is installed succesfully ')

        os.system("clear")
        def ma_ip():
            url='https://www.myexternalip.com/raw'
            get_ip= requests.get(url,proxies=dict(http='socks5://127.0.0.1:9050',https='socks5://127.0.0.1:9050'))
            return get_ip.text

        def change():
            os.system("service tor reload")
            print ('[+] Your IP has been Changed to : '+str(ma_ip()))

        print('''\033[1;32;40m \n
        ░█▀█░█░█░▀█▀░█▀█░░░▀█▀░█▀█░█▀▄
        ░█▀█░█░█░░█░░█░█░░░░█░░█░█░█▀▄
        ░▀░▀░▀▀▀░░▀░░▀▀▀░░░░▀░░▀▀▀░▀░▀
                        V 2.1
        ''')
        os.system("service tor start")

        time.sleep(3)
        print("\033[1;32;40m change your  SOCKES to 127.0.0.1:9050 \n")
        os.system("service tor start")
        x = input("[+] time to change Ip in Sec [type=60] >> ")
        lin = input("[+] how many time do you want to change your ip [type=1000]for infinte ip change type [0] >>")
        if int(lin) ==int(0):

            while True:
                try:
                    time.sleep(int(x))
                    change()
                except KeyboardInterrupt:

                    print('\nauto tor is closed ')
                    quit()

        else:
            for i in range(int(lin)):
                    time.sleep(int(x))
                    change()
        
def KeyLogger():
    while True:
        os.system('cls' if os.name == "nt" else "clear")
        

#Run
mExodia()