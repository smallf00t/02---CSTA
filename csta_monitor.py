#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import sys
import time
import logging
import binascii
import struct
import select
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("csta_monitor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration de la connexion
PABX_IP = "10.134.3.13"    # Adresse IP du PABX OXE (modifiée selon vos logs)
PABX_PORT = 2555           # Port standard CSTA Telnet pour OXE
DEVICE_ID = "29707"        # Numéro du poste à surveiller
RECONNECT_DELAY = 10       # Délai en secondes avant tentative de reconnexion
KEEPALIVE_INTERVAL = 20    # Intervalle de keepalive en secondes (réduit)
SOCKET_TIMEOUT = 5         # Timeout pour les opérations socket (en secondes)

# Codes d'événements (basés sur les logs fournis)
EVENT_TYPES = {
    "EVT_DELIVERED": 4,       # Appel entrant (A3)
    "EVT_CONNECTION_CLEARED": 3, # Fin d'appel (A2)
    "EVT_DIVERTED": 5,        # Redirection d'appel (A4)
    "EVT_ESTABLISHED": 1,     # Appel connecté
    "EVT_ORIGINATED": 7       # Appel sortant
}

# Codes des causes (basés sur les logs fournis)
CAUSE_CODES = {
    48: "normalClearing",
    22: "newCall",
    11: "callPickup"
}

# Format des messages CSTA pour l'OXE
def format_identification():
    """Prépare le message d'identification initial"""
    return "42"

def format_start_monitor(device_id, invoke_id=1):
    """Prépare le message de démarrage de monitoring"""
    device_id_hex = ''.join([hex(ord(c))[2:].zfill(2) for c in device_id])
    invoke_id_hex = hex(invoke_id)[2:].zfill(2)
    message = f"00 11 A1 0F 02 01 {invoke_id_hex} 02 01 47 30 07 80 05 {device_id_hex}"
    return message.replace(" ", "")

def format_snapshot_device(device_id, invoke_id=3):
    """Prépare le message de demande de snapshot"""
    device_id_hex = ''.join([hex(ord(c))[2:].zfill(2) for c in device_id])
    invoke_id_hex = hex(invoke_id)[2:].zfill(2)
    message = f"00 0F A1 0D 02 01 {invoke_id_hex} 02 01 4A 80 05 {device_id_hex}"
    return message.replace(" ", "")

def format_keepalive(msg_id):
    """Prépare le message de keepalive"""
    msg_id_hex = hex(msg_id)[2:].zfill(4)
    message = f"00 0C A1 0A 02 02 {msg_id_hex} 02 01 34 0A 01 02"
    return message.replace(" ", "")

def format_keepalive_response(msg_id):
    """Prépare la réponse au keepalive"""
    msg_id_hex = hex(msg_id)[2:].zfill(4)
    message = f"00 0D A2 0B 02 02 {msg_id_hex} 30 05 02 01 34 05 00"
    return message.replace(" ", "")

def hex_to_bytes(hex_str):
    """Convertit une chaîne hexadécimale en bytes"""
    # Supprime les espaces si présents
    hex_str = hex_str.replace(" ", "")
    return binascii.unhexlify(hex_str)

def bytes_to_hex(data):
    """Convertit des bytes en chaîne hexadécimale formatée"""
    hex_str = binascii.hexlify(data).decode('utf-8')
    # Formate en groupes de 2 caractères pour une meilleure lisibilité
    return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2)).upper()

def extract_string_from_hex(hex_str, start_idx, length):
    """Extrait une chaîne de caractères d'une chaîne hexadécimale"""
    hex_str = hex_str.replace(" ", "")
    char_hex = hex_str[start_idx:start_idx + length*2]
    result = ""
    for i in range(0, len(char_hex), 2):
        result += chr(int(char_hex[i:i+2], 16))
    return result

def connect_to_pabx():
    """Établit une connexion socket avec le PABX"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Configurer un timeout pour éviter les blocages
        sock.settimeout(SOCKET_TIMEOUT)
        
        # Sur les systèmes Windows, configurer des options supplémentaires si possible
        if hasattr(socket, 'TCP_KEEPIDLE') and hasattr(socket, 'TCP_KEEPINTVL') and hasattr(socket, 'TCP_KEEPCNT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)  # Commencer à envoyer les keepalives après 30s
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)  # Envoyer un keepalive toutes les 5s
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)    # 5 échecs avant abandon
        
        sock.connect((PABX_IP, PABX_PORT))
        logger.info(f"Connexion établie avec le PABX {PABX_IP}:{PABX_PORT}")
        return sock
    except Exception as e:
        logger.error(f"Erreur de connexion au PABX: {e}")
        return None

def send_request(sock, hex_message):
    """Envoie une requête au PABX au format hexadécimal"""
    try:
        request_bytes = hex_to_bytes(hex_message)
        sock.sendall(request_bytes)
        logger.debug(f"Données envoyées vers Pabx: {bytes_to_hex(request_bytes)}")
        return True
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de la requête: {e}")
        return False

def receive_data(sock, timeout=0.5):
    """Reçoit les données du PABX avec gestion améliorée des erreurs"""
    try:
        data = b''
        original_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        
        try:
            chunk = sock.recv(4096)
            if chunk:
                data += chunk
                
                # Si le message est incomplet, essayer de recevoir le reste
                while True:
                    try:
                        sock.settimeout(0.1)  # Courte attente pour d'autres données
                        more = sock.recv(4096)
                        if more:
                            data += more
                        else:
                            break
                    except socket.timeout:
                        break
                    except (ConnectionError, ConnectionAbortedError, ConnectionResetError) as e:
                        logger.warning(f"Erreur de connexion pendant la réception incrémentale: {e}")
                        break
        except socket.timeout:
            pass  # Pas de données disponibles, ce n'est pas une erreur
        except (ConnectionError, ConnectionAbortedError, ConnectionResetError) as e:
            logger.warning(f"Connexion interrompue pendant la réception: {e}")
            return None
        
        try:
            sock.settimeout(original_timeout)  # Restaurer le timeout d'origine
        except Exception:
            pass  # Ignorer les erreurs lors de la restauration du timeout
        
        if data:
            logger.debug(f"Données reçues du Pabx: {bytes_to_hex(data)}")
            return data
        return None
    except Exception as e:
        logger.error(f"Erreur lors de la réception des données: {e}")
        return None

def parse_csta_message(data):
    """Analyse un message CSTA et extrait les informations pertinentes"""
    if not data:
        return None
    
    hex_data = bytes_to_hex(data)
    
    # Détecter le type de message
    message_info = {"raw_hex": hex_data}
    
    # Message de keepalive
    if "A1 0A" in hex_data and "02 01 34" in hex_data:
        message_info["type"] = "KEEPALIVE"
        # Extraire l'ID du message
        idx = hex_data.find("02 02")
        if idx > 0:
            msg_id_hex = hex_data[idx+5:idx+13].replace(" ", "")
            message_info["msg_id"] = int(msg_id_hex, 16)
        return message_info
    
    # Réponse à une demande de monitoring
    if "A2 2A" in hex_data and "02 01 47" in hex_data:
        message_info["type"] = "MONITOR_RESPONSE"
        # Extraire le CrossRefIdentifier
        if "55 04 01" in hex_data:
            idx = hex_data.find("55 04 01") + 9
            xref_hex = hex_data[idx:idx+8].replace(" ", "")
            message_info["cross_ref"] = int(xref_hex, 16)
        
        # Extraire l'ID d'invocation
        idx = hex_data.find("02 01")
        if idx > 0:
            invoke_id_hex = hex_data[idx+5:idx+7].replace(" ", "")
            message_info["invoke_id"] = int(invoke_id_hex, 16)
        
        return message_info
    
    # Réponse à un snapshot
    if "A2 1D" in hex_data and "02 01 4A" in hex_data:
        message_info["type"] = "SNAPSHOT_RESPONSE"
        # Extraire l'ID d'invocation
        idx = hex_data.find("02 01")
        if idx > 0:
            invoke_id_hex = hex_data[idx+5:idx+7].replace(" ", "")
            message_info["invoke_id"] = int(invoke_id_hex, 16)
        return message_info
    
    # Événement d'appel entrant (Delivered)
    if "A1 81" in hex_data and "A3" in hex_data:
        message_info["type"] = "EVENT"
        message_info["event_type"] = "EVT_DELIVERED"
        message_info["event_code"] = EVENT_TYPES["EVT_DELIVERED"]
        
        # Extraire le CallID
        idx = hex_data.find("82 02")
        if idx > 0:
            call_id_hex = hex_data[idx+6:idx+11].replace(" ", "")
            message_info["call_id"] = int(call_id_hex, 16)
        
        # Extraire le numéro appelant
        idx = hex_data.find("61")
        if idx > 0:
            # Trouver la longueur du numéro (généralement après 82 ou 84)
            len_idx = hex_data.find("82", idx)
            if len_idx > 0:
                len_idx += 3
                len_hex = hex_data[len_idx:len_idx+2].replace(" ", "")
                number_len = int(len_hex, 16)
                
                # Trouver le début du numéro (après la longueur)
                number_idx = hex_data.find(" ", len_idx) + 1
                number_hex = ""
                for i in range(number_len * 3):
                    if number_idx + i < len(hex_data):
                        number_hex += hex_data[number_idx + i]
                
                # Convertir en caractères
                number_hex = number_hex.replace(" ", "")
                calling_number = ""
                for i in range(0, len(number_hex), 2):
                    if i+2 <= len(number_hex):
                        calling_number += chr(int(number_hex[i:i+2], 16))
                
                message_info["calling_number"] = calling_number
        
        # Extraire le nom de l'appelant
        idx = hex_data.find("80", hex_data.find("A1"))
        if idx > 0:
            # Vérifier si c'est bien un nom et pas une autre donnée
            if "84 00" in hex_data[idx-20:idx+20]:
                len_idx = idx + 3
                len_hex = hex_data[len_idx:len_idx+2].replace(" ", "")
                try:
                    name_len = int(len_hex, 16)
                    if name_len > 0:
                        name_idx = hex_data.find(" ", len_idx) + 1
                        name_hex = ""
                        for i in range(name_len * 3):
                            if name_idx + i < len(hex_data):
                                name_hex += hex_data[name_idx + i]
                        
                        name_hex = name_hex.replace(" ", "")
                        caller_name = ""
                        for i in range(0, len(name_hex), 2):
                            if i+2 <= len(name_hex):
                                caller_name += chr(int(name_hex[i:i+2], 16))
                        
                        message_info["caller_name"] = caller_name
                except:
                    pass
        
        # Extraire le numéro appelé
        idx = hex_data.find("62")
        if idx > 0:
            # Trouver la longueur du numéro (généralement après 84)
            len_idx = hex_data.find("84", idx)
            if len_idx > 0:
                len_idx += 3
                len_hex = hex_data[len_idx:len_idx+2].replace(" ", "")
                number_len = int(len_hex, 16)
                
                # Trouver le début du numéro (après la longueur)
                number_idx = hex_data.find(" ", len_idx) + 1
                number_hex = ""
                for i in range(number_len * 3):
                    if number_idx + i < len(hex_data):
                        number_hex += hex_data[number_idx + i]
                
                # Convertir en caractères
                number_hex = number_hex.replace(" ", "")
                called_number = ""
                for i in range(0, len(number_hex), 2):
                    if i+2 <= len(number_hex):
                        called_number += chr(int(number_hex[i:i+2], 16))
                
                message_info["called_number"] = called_number
        
        return message_info
    
    # Événement de fin d'appel (Connection Cleared)
    if ("A1 5F" in hex_data or "A1 59" in hex_data) and "A2" in hex_data:
        message_info["type"] = "EVENT"
        message_info["event_type"] = "EVT_CONNECTION_CLEARED"
        message_info["event_code"] = EVENT_TYPES["EVT_CONNECTION_CLEARED"]
        
        # Extraire le CallID
        idx = hex_data.find("82 02")
        if idx > 0:
            call_id_hex = hex_data[idx+6:idx+11].replace(" ", "")
            message_info["call_id"] = int(call_id_hex, 16)
        
        # Extraire le périphérique de libération (releasingDevice)
        idx = hex_data.find("63")
        if idx > 0:
            # Trouver la longueur du numéro (généralement après 82 ou 84)
            len_idx = -1
            if "82" in hex_data[idx:idx+20]:
                len_idx = hex_data.find("82", idx) + 3
            elif "84" in hex_data[idx:idx+20]:
                len_idx = hex_data.find("84", idx) + 3
            
            if len_idx > 0:
                len_hex = hex_data[len_idx:len_idx+2].replace(" ", "")
                number_len = int(len_hex, 16)
                
                # Trouver le début du numéro (après la longueur)
                number_idx = hex_data.find(" ", len_idx) + 1
                number_hex = ""
                for i in range(number_len * 3):
                    if number_idx + i < len(hex_data):
                        number_hex += hex_data[number_idx + i]
                
                # Convertir en caractères
                number_hex = number_hex.replace(" ", "")
                releasing_device = ""
                for i in range(0, len(number_hex), 2):
                    if i+2 <= len(number_hex):
                        releasing_device += chr(int(number_hex[i:i+2], 16))
                
                message_info["releasing_device"] = releasing_device
        
        # Extraire la cause
        idx = hex_data.find("0A 01")
        if idx > 0:
            cause_hex = hex_data[idx+6:idx+8].replace(" ", "")
            cause_code = int(cause_hex, 16)
            message_info["cause_code"] = cause_code
            message_info["cause"] = CAUSE_CODES.get(cause_code, f"unknown({cause_code})")
        
        return message_info
    
    # Événement de redirection d'appel (Diverted)
    if "A1 64" in hex_data or "A1 62" in hex_data and "A4" in hex_data:
        message_info["type"] = "EVENT"
        message_info["event_type"] = "EVT_DIVERTED"
        message_info["event_code"] = EVENT_TYPES["EVT_DIVERTED"]
        
        # Extraire le CallID
        idx = hex_data.find("82 02")
        if idx > 0:
            call_id_hex = hex_data[idx+6:idx+11].replace(" ", "")
            message_info["call_id"] = int(call_id_hex, 16)
        
        # Extraire le périphérique de redirection
        idx1 = hex_data.find("63 07")
        if idx1 > 0:
            # Trouver la longueur du numéro (généralement après 84)
            len_idx = hex_data.find("84", idx1) + 3
            if len_idx > 3:
                len_hex = hex_data[len_idx:len_idx+2].replace(" ", "")
                number_len = int(len_hex, 16)
                
                # Trouver le début du numéro (après la longueur)
                number_idx = hex_data.find(" ", len_idx) + 1
                number_hex = ""
                for i in range(number_len * 3):
                    if number_idx + i < len(hex_data):
                        number_hex += hex_data[number_idx + i]
                
                # Convertir en caractères
                number_hex = number_hex.replace(" ", "")
                diverting_device = ""
                for i in range(0, len(number_hex), 2):
                    if i+2 <= len(number_hex):
                        diverting_device += chr(int(number_hex[i:i+2], 16))
                
                message_info["diverting_device"] = diverting_device
        
        # Extraire la nouvelle destination
        idx2 = hex_data.find("63 09")
        if idx2 > 0:
            # Trouver la longueur du numéro (généralement après 84)
            len_idx = hex_data.find("84", idx2) + 3
            if len_idx > 3:
                len_hex = hex_data[len_idx:len_idx+2].replace(" ", "")
                number_len = int(len_hex, 16)
                
                # Trouver le début du numéro (après la longueur)
                number_idx = hex_data.find(" ", len_idx) + 1
                number_hex = ""
                for i in range(number_len * 3):
                    if number_idx + i < len(hex_data):
                        number_hex += hex_data[number_idx + i]
                
                # Convertir en caractères
                number_hex = number_hex.replace(" ", "")
                new_destination = ""
                for i in range(0, len(number_hex), 2):
                    if i+2 <= len(number_hex):
                        new_destination += chr(int(number_hex[i:i+2], 16))
                
                message_info["new_destination"] = new_destination
        
        # Extraire la cause
        idx = hex_data.find("0A 01")
        if idx > 0:
            cause_hex = hex_data[idx+6:idx+8].replace(" ", "")
            cause_code = int(cause_hex, 16)
            message_info["cause_code"] = cause_code
            message_info["cause"] = CAUSE_CODES.get(cause_code, f"unknown({cause_code})")
        
        return message_info
    
    # Si le type de message n'est pas identifié
    message_info["type"] = "UNKNOWN"
    return message_info

def main():
    """Fonction principale"""
    logger.info(f"Démarrage de l'écouteur CSTA pour le poste {DEVICE_ID} sur le PABX {PABX_IP}")
    
    # Compteurs pour les IDs de message
    invoke_id = 1
    keepalive_msg_id = 8000
    connection_attempts = 0
    
    # État de supervision des postes
    monitored_devices = {}
    
    while True:
        try:
            # Incrémenter le compteur de tentatives
            connection_attempts += 1
            
            sock = connect_to_pabx()
            if not sock:
                logger.error(f"Échec de connexion (tentative {connection_attempts})")
                time.sleep(RECONNECT_DELAY)
                continue
            
            # Réinitialiser le compteur de tentatives après une connexion réussie
            connection_attempts = 0
            
            # Identification initiale
            logger.info("Envoi de l'identification de l'application")
            if not send_request(sock, format_identification()):
                logger.error("Échec de l'identification")
                sock.close()
                time.sleep(RECONNECT_DELAY)
                continue
            
            # Attendre la réponse à l'identification
            time.sleep(1)
            response = receive_data(sock)
            
            # Demande de supervision du poste principal
            logger.info(f"Démarrage de la supervision du poste {DEVICE_ID}")
            monitor_msg = format_start_monitor(DEVICE_ID, invoke_id)
            if not send_request(sock, monitor_msg):
                logger.error(f"Échec de la demande de supervision pour {DEVICE_ID}")
                sock.close()
                time.sleep(RECONNECT_DELAY)
                continue
            
            invoke_id += 1
            time.sleep(1)
            response = receive_data(sock)
            
            # Traiter la réponse de supervision
            if response:
                msg_info = parse_csta_message(response)
                if msg_info and msg_info.get("type") == "MONITOR_RESPONSE":
                    cross_ref = msg_info.get("cross_ref")
                    if cross_ref:
                        logger.info(f"Poste {DEVICE_ID} supervisé (CrossRef: {cross_ref})")
                        monitored_devices[DEVICE_ID] = {"cross_ref": cross_ref}
                        
                        # Demande de snapshot pour obtenir l'état initial
                        snapshot_msg = format_snapshot_device(DEVICE_ID, invoke_id)
                        send_request(sock, snapshot_msg)
                        invoke_id += 1
                        time.sleep(1)
                        receive_data(sock)
            
            # Initialisation de l'heure du dernier keepalive
            last_keepalive_time = time.time()
            last_activity_time = time.time()
            
            # Boucle principale de réception des événements
            logger.info("En attente d'événements CSTA...")
            while True:
                try:
                    current_time = time.time()
                    
                    # Détection d'inactivité prolongée
                    if current_time - last_activity_time > KEEPALIVE_INTERVAL * 3:
                        logger.warning(f"Aucune activité détectée depuis {KEEPALIVE_INTERVAL * 3} secondes, vérification de la connexion...")
                        try:
                            # Test de connexion simple
                            sock.settimeout(2)
                            sock.send(b"\x00")  # Tentative d'envoi d'un octet
                            logger.debug("Test de connexion réussi")
                        except Exception as e:
                            logger.error(f"Connexion perdue lors du test: {e}")
                            raise ConnectionError("Connexion perdue")
                    
                    # Gestion du keepalive
                    if current_time - last_keepalive_time > KEEPALIVE_INTERVAL:
                        logger.debug("Envoi du message keepalive")
                        keepalive_msg = format_keepalive(keepalive_msg_id)
                        if not send_request(sock, keepalive_msg):
                            logger.warning("Échec de l'envoi du keepalive")
                            raise ConnectionError("Échec du keepalive")
                        
                        keepalive_msg_id += 1
                        if keepalive_msg_id > 65000:  # Éviter le dépassement
                            keepalive_msg_id = 8000
                        last_keepalive_time = current_time
                        last_activity_time = current_time
                    
                    # Réception et traitement des messages
                    data = receive_data(sock)
                    if data:
                        last_activity_time = time.time()  # Mettre à jour l'heure de dernière activité
                        
                        msg_info = parse_csta_message(data)
                        if msg_info:
                            if msg_info["type"] == "KEEPALIVE":
                                # Répondre au keepalive
                                msg_id = msg_info.get("msg_id")
                                if msg_id:
                                    response = format_keepalive_response(msg_id)
                                    send_request(sock, response)
                                    logger.debug(f"Réponse au keepalive envoyée (ID: {msg_id})")
                            
                            elif msg_info["type"] == "EVENT":
                                if msg_info["event_type"] == "EVT_DELIVERED":
                                    # Appel entrant
                                    call_id = msg_info.get("call_id", "inconnu")
                                    calling = msg_info.get("calling_number", "inconnu")
                                    called = msg_info.get("called_number", DEVICE_ID)
                                    caller_name = msg_info.get("caller_name", "")
                                    
                                    if caller_name:
                                        logger.info(f"Appel entrant: {calling} ({caller_name}) → {called} [ID: {call_id}]")
                                    else:
                                        logger.info(f"Appel entrant: {calling} → {called} [ID: {call_id}]")
                                
                                elif msg_info["event_type"] == "EVT_CONNECTION_CLEARED":
                                    # Fin d'appel
                                    call_id = msg_info.get("call_id", "inconnu")
                                    releasing = msg_info.get("releasing_device", "inconnu")
                                    cause = msg_info.get("cause", "inconnu")
                                    
                                    logger.info(f"Fin d'appel: {releasing} a raccroché [ID: {call_id}] - Cause: {cause}")
                                
                                elif msg_info["event_type"] == "EVT_DIVERTED":
                                    # Redirection d'appel
                                    call_id = msg_info.get("call_id", "inconnu")
                                    diverting = msg_info.get("diverting_device", DEVICE_ID)
                                    destination = msg_info.get("new_destination", "inconnu")
                                    cause = msg_info.get("cause", "inconnu")
                                    
                                    logger.info(f"Redirection d'appel: {diverting} → {destination} [ID: {call_id}] - Cause: {cause}")
                    
                    # Petite pause pour éviter de surcharger le CPU
                    time.sleep(0.1)
                    
                except (ConnectionError, ConnectionResetError, ConnectionAbortedError, socket.error) as e:
                    logger.error(f"Erreur de connexion dans la boucle principale: {e}")
                    break
            
            # Fermer la socket en cas d'erreur
            try:
                sock.close()
                logger.info("Connexion fermée")
            except Exception as e:
                logger.debug(f"Erreur lors de la fermeture de la socket: {e}")
        
        except Exception as e:
            logger.error(f"Exception générale: {e}")
        
        # Attendre avant de tenter une reconnexion
        logger.info(f"Tentative de reconnexion dans {RECONNECT_DELAY} secondes...")
        time.sleep(RECONNECT_DELAY)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Programme arrêté par l'utilisateur")
    except Exception as e:
        logger.critical(f"Erreur fatale: {e}")
        sys.exit(1)