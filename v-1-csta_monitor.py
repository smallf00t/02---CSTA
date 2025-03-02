#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# v1.0.1    

import socket
import sys
import time
import logging
import binascii
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
PABX_IP = "10.134.3.13"  # Adresse IP du PABX OXE
PABX_PORT = 2555         # Port standard CSTA Telnet pour OXE
DEVICE_ID = "29707"      # Numéro du poste à surveiller
RECONNECT_DELAY = 30     # Délai avant reconnexion en cas d'échec
SESSION_TIME = 300       # Durée maximale d'une session en secondes (5 minutes)
KEEPALIVE_INTERVAL = 15  # Intervalle d'envoi des keepalives en secondes

def bytes_to_hex(data):
    """Convertit des bytes en chaîne hexadécimale formatée"""
    if not data:
        return "AUCUNE DONNÉE"
    hex_str = binascii.hexlify(data).decode('utf-8')
    return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2)).upper()

def hex_to_bytes(hex_str):
    """Convertit une chaîne hexadécimale en bytes"""
    hex_str = hex_str.replace(" ", "")
    return binascii.unhexlify(hex_str)

def format_keepalive(invoke_id):
    """Format du keepalive basé sur les logs"""
    id_hi = (invoke_id >> 8) & 0xFF
    id_lo = invoke_id & 0xFF
    
    # Format : 00 0C A1 0A 02 02 [id_hi] [id_lo] 02 01 34 0A 01 02
    cmd = f"00 0C A1 0A 02 02 {id_hi:02X} {id_lo:02X} 02 01 34 0A 01 02"
    return hex_to_bytes(cmd)

def format_keepalive_response(id_hi, id_lo):
    """Format de la réponse au keepalive"""
    return hex_to_bytes(f"00 0D A2 0B 02 02 {id_hi:02X} {id_lo:02X} 30 05 02 01 34 05 00")

def extract_ascii_number(hex_data, start_idx, length=10):
    """Extrait un numéro de téléphone à partir d'une position dans les données hex"""
    try:
        number = ""
        for i in range(0, length*3, 3):
            if start_idx + i >= len(hex_data):
                break
            byte_hex = hex_data[start_idx + i:start_idx + i + 2]
            if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                number += chr(int(byte_hex, 16))
            else:
                # Si ce n'est pas un chiffre, on s'arrête
                if i > 0:  # Seulement si on a déjà trouvé des chiffres
                    break
        return number
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction du numéro: {e}")
        return ""

def extract_ascii_string(hex_data, start_idx, length=20):
    """Extrait une chaîne de caractères à partir d'une position dans les données hex"""
    try:
        result = ""
        for i in range(0, length*3, 3):
            if start_idx + i >= len(hex_data):
                break
            byte_hex = hex_data[start_idx + i:start_idx + i + 2]
            byte_val = int(byte_hex, 16)
            if 32 <= byte_val <= 126:  # Caractères ASCII imprimables
                result += chr(byte_val)
            else:
                if i > 0:  # Seulement si on a déjà trouvé des caractères
                    break
        return result
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction de la chaîne: {e}")
        return ""

def parse_event(data):
    """Analyse les événements CSTA"""
    hex_data = bytes_to_hex(data)
    
    # Keepalive du PABX (détection basée sur la structure observée dans les logs)
    if "A1 0A" in hex_data and "02 01 34" in hex_data:
        try:
            # Extraire l'ID du keepalive
            idx = hex_data.find("02 02") + 6
            id_hi = int(hex_data[idx:idx+2], 16)
            id_lo = int(hex_data[idx+3:idx+5], 16)
            keepalive_id = (id_hi << 8) | id_lo
            
            logger.debug(f"Keepalive PABX reçu - ID: {keepalive_id:04X}")
            
            # Générer la réponse au keepalive
            return {
                "type": "KEEPALIVE",
                "id": keepalive_id,
                "response": format_keepalive_response(id_hi, id_lo)
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du keepalive: {e}")
    
    # Détection d'appel entrant (contient A3 près de A0)
    if "A0" in hex_data and "A3" in hex_data and len(hex_data) > 100:
        try:
            call_info = {"type": "INCOMING_CALL", "raw_hex": hex_data}
            
            # Extraire le numéro d'appel (Call ID)
            if "82 02" in hex_data:
                call_id_idx = hex_data.find("82 02") + 6
                call_id_hex = hex_data[call_id_idx:call_id_idx+5].replace(" ", "")
                call_info["call_id"] = int(call_id_hex, 16)
            
            # Extraire le numéro appelant (après "61" ou "61 0D 82")
            if "61 0D 82" in hex_data:
                caller_idx = hex_data.find("61 0D 82") + 9
                length_idx = caller_idx - 3
                length = int(hex_data[length_idx:length_idx+2], 16)
                
                # Trouver les indices du numéro dans la chaîne hex
                start_idx = caller_idx
                caller = ""
                for i in range(length):
                    byte_pos = start_idx + i*3
                    if byte_pos + 2 <= len(hex_data):
                        byte_hex = hex_data[byte_pos:byte_pos+2]
                        caller += chr(int(byte_hex, 16))
                
                call_info["caller_number"] = caller
            
            # Extraire le numéro appelé (après "62")
            if "62 07 84 05" in hex_data:
                called_idx = hex_data.find("62 07 84 05") + 12
                called = extract_ascii_number(hex_data, called_idx)
                call_info["called_number"] = called
            
            # Extraire le nom appelant (plus complexe, souvent après "80" dans certains segments)
            name_patterns = ["80 0", "80 1"]
            for pattern in name_patterns:
                if pattern in hex_data:
                    name_idx = hex_data.find(pattern) + 6
                    name = extract_ascii_string(hex_data, name_idx)
                    if name and len(name) > 2:  # Nom valide si plus de 2 caractères
                        call_info["caller_name"] = name
                        break
            
            # Extraction de l'heure (après "17 0D")
            if "17 0D" in hex_data:
                time_idx = hex_data.find("17 0D") + 6
                time_str = ""
                for i in range(14):  # Format: YYMMDDhhmmssZ
                    byte_pos = time_idx + i*3
                    if byte_pos + 2 <= len(hex_data):
                        byte_hex = hex_data[byte_pos:byte_pos+2]
                        time_str += chr(int(byte_hex, 16))
                
                if time_str:
                    try:
                        # Format YYMMDDhhmmssZ
                        year = f"20{time_str[0:2]}"
                        month = time_str[2:4]
                        day = time_str[4:6]
                        hour = time_str[6:8]
                        minute = time_str[8:10]
                        second = time_str[10:12]
                        call_info["timestamp"] = f"{year}-{month}-{day} {hour}:{minute}:{second}"
                    except:
                        pass
            
            # Log formaté
            log_msg = f"Appel entrant détecté - ID: {call_info.get('call_id', 'inconnu')}"
            if 'caller_number' in call_info:
                log_msg += f", De: {call_info['caller_number']}"
            if 'caller_name' in call_info:
                log_msg += f" ({call_info['caller_name']})"
            if 'called_number' in call_info:
                log_msg += f", Vers: {call_info['called_number']}"
            if 'timestamp' in call_info:
                log_msg += f", Heure: {call_info['timestamp']}"
                
            logger.info(log_msg)
            logger.debug(f"Trame brute: {hex_data}")
            
            return call_info
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de l'appel entrant: {e}")
    
    # Détection de fin d'appel
    if "A2" in hex_data and ("30 21" in hex_data or "30 1B" in hex_data) and len(hex_data) > 50:
        try:
            call_info = {"type": "CALL_ENDED", "raw_hex": hex_data}
            
            # Extraire le numéro d'appel (Call ID)
            if "82 02" in hex_data:
                call_id_idx = hex_data.find("82 02") + 6
                call_id_hex = hex_data[call_id_idx:call_id_idx+5].replace(" ", "")
                call_info["call_id"] = int(call_id_hex, 16)
            
            # Extraire le numéro du périphérique qui raccroche
            if "63 0" in hex_data:
                device_idx = hex_data.find("63 0") + 9
                device = extract_ascii_number(hex_data, device_idx)
                call_info["hanging_device"] = device
            
            # Extraire la cause (après "0A 01")
            if "0A 01" in hex_data:
                cause_idx = hex_data.find("0A 01") + 6
                cause_code = int(hex_data[cause_idx:cause_idx+2], 16)
                
                # Mappage des codes de cause
                causes = {
                    48: "normalClearing",
                    22: "newCall",
                    11: "callPickup"
                }
                
                call_info["cause_code"] = cause_code
                call_info["cause"] = causes.get(cause_code, f"unknown({cause_code})")
            
            # Log formaté
            log_msg = f"Fin d'appel détectée - ID: {call_info.get('call_id', 'inconnu')}"
            if 'hanging_device' in call_info:
                log_msg += f", Périphérique: {call_info['hanging_device']}"
            if 'cause' in call_info:
                log_msg += f", Cause: {call_info['cause']}"
                
            logger.info(log_msg)
            logger.debug(f"Trame brute: {hex_data}")
            
            return call_info
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de la fin d'appel: {e}")
    
    # Détection de redirection d'appel
    if "A4" in hex_data and len(hex_data) > 50:
        try:
            call_info = {"type": "CALL_DIVERTED", "raw_hex": hex_data}
            
            # Extraire le numéro d'appel (Call ID)
            if "82 02" in hex_data:
                call_id_idx = hex_data.find("82 02") + 6
                call_id_hex = hex_data[call_id_idx:call_id_idx+5].replace(" ", "")
                call_info["call_id"] = int(call_id_hex, 16)
            
            # Extraire le numéro du périphérique qui redirige
            if "63 07 84 05" in hex_data:
                from_idx = hex_data.find("63 07 84 05") + 12
                from_device = extract_ascii_number(hex_data, from_idx)
                call_info["from_device"] = from_device
            
            # Extraire le numéro de destination
            if "63 09 84 07" in hex_data:
                to_idx = hex_data.find("63 09 84 07") + 12
                to_device = extract_ascii_number(hex_data, to_idx)
                call_info["to_device"] = to_device
            
            # Extraire la cause (après "0A 01")
            if "0A 01" in hex_data:
                cause_idx = hex_data.find("0A 01") + 6
                cause_code = int(hex_data[cause_idx:cause_idx+2], 16)
                
                # Mappage des codes de cause
                causes = {
                    48: "normalClearing",
                    22: "newCall",
                    11: "callPickup"
                }
                
                call_info["cause_code"] = cause_code
                call_info["cause"] = causes.get(cause_code, f"unknown({cause_code})")
            
            # Log formaté
            log_msg = f"Redirection d'appel détectée - ID: {call_info.get('call_id', 'inconnu')}"
            if 'from_device' in call_info:
                log_msg += f", De: {call_info['from_device']}"
            if 'to_device' in call_info:
                log_msg += f", Vers: {call_info['to_device']}"
            if 'cause' in call_info:
                log_msg += f", Cause: {call_info['cause']}"
                
            logger.info(log_msg)
            logger.debug(f"Trame brute: {hex_data}")
            
            return call_info
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de la redirection d'appel: {e}")
    
    # Si on ne reconnaît pas le type de message
    logger.debug(f"Trame non reconnue: {hex_data}")
    return {"type": "UNKNOWN", "raw_hex": hex_data}

def connect_and_monitor():
    """Établit une connexion avec le PABX et surveille les événements"""
    try:
        # Création de la socket
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.settimeout(10)  # Timeout de 10 secondes
        
        # Connexion au PABX
        logger.info(f"Tentative de connexion au PABX {PABX_IP}:{PABX_PORT}")
        client_sock.connect((PABX_IP, PABX_PORT))
        logger.info("Connexion au PABX réussie")
        
        # ÉTAPE 1: Envoi de l'identification
        ident_command = b"\x42"
        logger.info(f"Envoi de l'identification: {bytes_to_hex(ident_command)}")
        client_sock.sendall(ident_command)
        
        # Attente d'une réponse
        try:
            response = client_sock.recv(1024)
            logger.info(f"Réponse à l'identification: {bytes_to_hex(response)}")
            
            # Attendre un peu
            time.sleep(2)
            
            # ÉTAPE 2: Envoi de la commande de session
            session_cmd = hex_to_bytes("00 46 60 44 80 02 07 80 A1 07 06 05 2B 0C 00 81 34 BE 35 28 33 06 07 2B 0C 00 81 5A 81 48 A0 28 30 26 03 02 03 C0 30 16 80 04 03 E7 B6 48 81 06 02 5F FD 03 FE A0 83 02 06 C0 84 02 03 F0 30 08 82 02 03 D8 83 02 06 C0")
            logger.info(f"Envoi de la commande session: {bytes_to_hex(session_cmd)}")
            client_sock.sendall(session_cmd)
            
            try:
                response = client_sock.recv(1024)
                logger.info(f"Réponse à la commande session: {bytes_to_hex(response)}")
                
                time.sleep(2)
                
                # ÉTAPE 3: Envoi de la commande Start Monitor
                monitor_cmd = hex_to_bytes("00 11 A1 0F 02 01 01 02 01 47 30 07 80 05 32 39 37 30 37")
                logger.info(f"Envoi de Start Monitor: {bytes_to_hex(monitor_cmd)}")
                client_sock.sendall(monitor_cmd)
                
                try:
                    response = client_sock.recv(1024)
                    logger.info(f"Réponse à Start Monitor: {bytes_to_hex(response)}")
                    
                    # ÉTAPE 4: Envoi de la commande Snapshot
                    snapshot_cmd = hex_to_bytes("00 0F A1 0D 02 01 03 02 01 4A 80 05 32 39 37 30 37")
                    logger.info(f"Envoi de la commande Snapshot: {bytes_to_hex(snapshot_cmd)}")
                    client_sock.sendall(snapshot_cmd)
                    
                    # Tenter de recevoir une réponse au snapshot
                    try:
                        response = client_sock.recv(1024)
                        logger.info(f"Réponse au Snapshot: {bytes_to_hex(response)}")
                    except socket.timeout:
                        logger.warning("Pas de réponse au Snapshot (ce n'est pas forcément une erreur)")
                    
                    # Passer en mode surveillance
                    client_sock.setblocking(False)
                    
                    # Variables pour la gestion des keepalives
                    invoke_id = 1
                    last_keepalive_time = time.time()
                    
                    # Boucle principale de surveillance
                    start_time = time.time()
                    logger.info("Début de la surveillance des événements...")
                    
                    # while time.time() - start_time < SESSION_TIME:
                    while True:
                        # Envoi périodique de keepalives
                        current_time = time.time()
                        if current_time - last_keepalive_time >= KEEPALIVE_INTERVAL:
                            keepalive = format_keepalive(invoke_id)
                            logger.debug(f"Envoi keepalive (ID: {invoke_id:04X}): {bytes_to_hex(keepalive)}")
                            try:
                                client_sock.sendall(keepalive)
                                last_keepalive_time = current_time
                                invoke_id = (invoke_id + 1) % 0xFFFF
                            except socket.error as e:
                                logger.error(f"Erreur lors de l'envoi du keepalive: {e}")
                                break
                        
                        # Réception des événements
                        try:
                            data = client_sock.recv(4096)
                            if data:
                                event_info = parse_event(data)
                                
                                # Afficher les données brutes et traitées
                                logger.info(f"Événement reçu: {bytes_to_hex(data)}")
                                
                                # Si c'est un keepalive, envoyer la réponse
                                if event_info and event_info.get("type") == "KEEPALIVE":
                                    try:
                                        response = event_info.get("response")
                                        if response:
                                            client_sock.sendall(response)
                                            logger.debug(f"Réponse au keepalive envoyée: {bytes_to_hex(response)}")
                                    except socket.error as e:
                                        logger.error(f"Erreur lors de l'envoi de la réponse au keepalive: {e}")
                                        break
                        except (socket.error, BlockingIOError):
                            pass  # Pas de données disponibles
                        
                        # Petite pause pour éviter de surcharger le CPU
                        time.sleep(0.1)
                    
                    logger.info(f"Fin de la session de surveillance (durée: {SESSION_TIME} secondes)")
                    
                except socket.timeout:
                    logger.warning("Pas de réponse à Start Monitor")
            except socket.timeout:
                logger.warning("Pas de réponse à la commande session")
        except socket.timeout:
            logger.warning("Pas de réponse à l'identification")
        
        # Fermeture propre de la connexion
        try:
            client_sock.close()
            logger.info("Connexion fermée")
        except:
            pass
            
        return True
        
    except socket.error as e:
        logger.error(f"Erreur de socket: {e}")
        try:
            client_sock.close()
        except:
            pass
        return False

def main():
    """Boucle principale avec reconnexions périodiques"""
    logger.info(f"Démarrage de l'écouteur CSTA pour le poste {DEVICE_ID}")
    
    while True:
        try:
            success = connect_and_monitor()
            
            if success:
                logger.info(f"Session terminée normalement, reconnexion dans {RECONNECT_DELAY} secondes")
            else:
                logger.warning(f"Session terminée avec erreur, reconnexion dans {RECONNECT_DELAY} secondes")
                
            time.sleep(RECONNECT_DELAY)
        except Exception as e:
            logger.error(f"Erreur inattendue: {e}")
            time.sleep(RECONNECT_DELAY)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Programme arrêté par l'utilisateur")
    except Exception as e:
        logger.critical(f"Erreur fatale: {e}")
        sys.exit(1)