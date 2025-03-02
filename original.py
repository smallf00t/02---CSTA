#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# CSTA Monitor for OXE PBX - Version Simplifiée

import socket
import sys
import time
import logging
import binascii
import json
import signal
import argparse
import json
import os
from datetime import datetime
import paho.mqtt.client as mqtt

# Ajout du parser d'arguments pour --printLog et --trace
parser = argparse.ArgumentParser(description='CSTA Monitor pour OXE PBX')
parser.add_argument('--printLog', action='store_true', help='Activer l\'affichage des logs dans la console')
parser.add_argument('--trace', action='store_true', help='Activer l\'écriture des logs dans le fichier csta_monitor.log')
parser.add_argument('--config', default='config.json', help='Chemin vers le fichier de configuration (par défaut: config.json)')
args = parser.parse_args()


# Configuration du logging - Toujours avoir au moins un handler pour le fonctionnement interne
handlers = []
if args.trace:
    handlers.append(logging.FileHandler("csta_monitor.log"))
if args.printLog:
    handlers.append(logging.StreamHandler(sys.stdout))
if not handlers:  
    # Si aucun argument n'est fourni, utiliser un NullHandler pour les messages
    # mais garder un FileHandler minimal pour les erreurs critiques et les fonctions internes
    null_handler = logging.NullHandler()
    null_handler.setLevel(logging.INFO)  # Ignorer les messages INFO normaux
    handlers.append(null_handler)
    
    # Créer un handler pour les erreurs critiques uniquement
    error_handler = logging.FileHandler("csta_error.log")
    error_handler.setLevel(logging.ERROR)  # Capturer uniquement ERROR et CRITICAL
    handlers.append(error_handler)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=handlers
)
logger = logging.getLogger(__name__)
class CSTAMonitor:

    def __init__(self, print_log=False, config_file='config.json'):
        """Initialise le CSTA Monitor avec les paramètres par défaut"""
        # Flag pour activer/désactiver les print
        self.print_log = print_log
        
        # Valeurs par défaut
        self.PABX_IP = "10.134.100.113"
        self.PABX_PORT = 2555
        self.MQTT_BROKER = "10.208.4.11"
        self.MQTT_PORT = 1883
        self.MQTT_TOPIC = "pabx/csta/monitoring"
        self.MQTT_USER = "smallfoot"
        self.MQTT_PASSWORD = "mdpsfi"
        
        # Liste par défaut des postes
        default_devices = ["24001", "24002", "24003"]
        self.DEVICES_TO_MONITOR = default_devices.copy()
        
        # Message d'erreur standard pour fichier manquant
        config_error_msg = f"Erreur: Fichier de configuration {config_file} introuvable ou invalide. "
        config_error_msg += "Veuillez créer un fichier JSON avec la structure suivante:\n"
        config_error_msg += '{\n'
        config_error_msg += '  "pabx": {\n'
        config_error_msg += '    "ip": "10.134.100.113",\n'
        config_error_msg += '    "port": 2555\n'
        config_error_msg += '  },\n'
        config_error_msg += '  "mqtt": {\n'
        config_error_msg += '    "broker": "10.208.4.11",\n'
        config_error_msg += '    "port": 1883,\n'
        config_error_msg += '    "topic": "pabx/csta/monitoring",\n'
        config_error_msg += '    "user": "smallfoot",\n'
        config_error_msg += '    "password": "mdpsfi"\n'
        config_error_msg += '  },\n'
        config_error_msg += '  "devices": {\n'
        config_error_msg += '    "nom_poste1": "123456",\n'
        config_error_msg += '    "nom_poste2": "123457"\n'
        config_error_msg += '  }\n'
        config_error_msg += '}'
        
        # Charger la configuration depuis le fichier
        config_loaded = False
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config_data = json.load(f)
                    
                    # Extraire les informations du PABX
                    if "pabx" in config_data:
                        pabx_config = config_data["pabx"]
                        self.PABX_IP = pabx_config.get("ip", self.PABX_IP)
                        self.PABX_PORT = pabx_config.get("port", self.PABX_PORT)
                    
                    # Extraire les informations MQTT
                    if "mqtt" in config_data:
                        mqtt_config = config_data["mqtt"]
                        self.MQTT_BROKER = mqtt_config.get("broker", self.MQTT_BROKER)
                        self.MQTT_PORT = mqtt_config.get("port", self.MQTT_PORT)
                        self.MQTT_TOPIC = mqtt_config.get("topic", self.MQTT_TOPIC)
                        self.MQTT_USER = mqtt_config.get("user", self.MQTT_USER)
                        self.MQTT_PASSWORD = mqtt_config.get("password", self.MQTT_PASSWORD)
                    
                    # Extraire la liste des postes
                    if "devices" in config_data:
                        self.DEVICES_TO_MONITOR = []
                        for name, device_id in config_data["devices"].items():
                            self.DEVICES_TO_MONITOR.append(str(device_id))
                    
                    config_loaded = True
                    logger.info(f"Configuration chargée depuis {config_file}")
                    logger.info(f"PABX: {self.PABX_IP}:{self.PABX_PORT}")
                    logger.info(f"MQTT: {self.MQTT_BROKER}:{self.MQTT_PORT}")
                    logger.info(f"Postes: {len(self.DEVICES_TO_MONITOR)} trouvés")
                    
                    if self.print_log:
                        print(f"Configuration chargée depuis {config_file}")
                        print(f"PABX: {self.PABX_IP}:{self.PABX_PORT}")
                        print(f"MQTT: {self.MQTT_BROKER}:{self.MQTT_PORT}")
                        print(f"Postes: {len(self.DEVICES_TO_MONITOR)} trouvés")
            else:
                # Fichier non trouvé - on affiche toujours le message d'erreur
                logger.error(config_error_msg)
                if self.print_log:
                    print(config_error_msg)
        except Exception as e:
            error_msg = f"Erreur lors de la lecture du fichier de configuration: {e}"
            logger.error(error_msg)
            logger.error(config_error_msg)  # Toujours afficher le modèle
            if self.print_log:
                print(error_msg)
                print(config_error_msg)  # Toujours afficher le modèle
        
        # Si la configuration n'a pas pu être chargée, indiquer l'utilisation des valeurs par défaut
        if not config_loaded:
            default_msg = f"Utilisation des paramètres par défaut:"
            default_msg += f"\n- PABX: {self.PABX_IP}:{self.PABX_PORT}"
            default_msg += f"\n- MQTT: {self.MQTT_BROKER}:{self.MQTT_PORT}"
            default_msg += f"\n- Postes: {self.DEVICES_TO_MONITOR}"
            
            logger.warning(default_msg)
            if self.print_log:
                print(default_msg)
        
        # Reste du code __init__ inchangé
        self.RECONNECT_DELAY = 30      # secondes
        self.KEEPALIVE_INTERVAL = 30   # secondes
        
        self.mqtt_client = None
        
        # Gestion des signaux
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Suivi des invocations
        self.last_invoke_id = 1

        # Suivi des appels actifs
        self.active_calls = {}  # Dictionnaire pour suivre les appels par ID

    
        # --- MQTT Handling ---
   
    def init_mqtt(self):
        """Initialise la connexion MQTT"""
        try:
            client = mqtt.Client()
            client.username_pw_set(self.MQTT_USER, self.MQTT_PASSWORD)
            client.on_connect = self.on_mqtt_connect
            client.on_message = self.on_mqtt_message  # Ajouter le callback pour les messages
            client.connect(self.MQTT_BROKER, self.MQTT_PORT, 60)
            
            # S'abonner au topic de pilotage
            client.subscribe(f"{self.MQTT_TOPIC}/pilote")
            logger.info(f"Abonnement au topic de pilotage: {self.MQTT_TOPIC}/pilote")
            
            client.loop_start()
            return client
        except Exception as e:
            logger.error(f"Erreur initialisation MQTT: {e}")
            return None
    
    def on_mqtt_connect(self, client, userdata, flags, rc):
        """Callback à la connexion MQTT"""
        if rc == 0:
            logger.info(f"MQTT connecté à {self.MQTT_BROKER}:{self.MQTT_PORT}")
            # Abonnement au topic de pilotage
            client.subscribe(f"{self.MQTT_TOPIC}/pilote")
            logger.info(f"Abonnement au topic de pilotage: {self.MQTT_TOPIC}/pilote")
            
            # Publier un message de démarrage
            self.send_mqtt_message({
                "type": "SYSTEM_STATUS",
                "status": "online",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        else:
            logger.error(f"Échec connexion MQTT, code: {rc}")

    def on_mqtt_message(self, client, userdata, msg):
        """Callback pour les messages MQTT reçus"""
        try:
            # Décodage du message
            payload_str = msg.payload.decode('utf-8')
            logger.info(f"Message MQTT reçu sur {msg.topic}: {payload_str}")
            
            # Vérifier si c'est le topic de pilotage
            if msg.topic == f"{self.MQTT_TOPIC}/pilote":
                # Parsing du JSON
                try:
                    data = json.loads(payload_str)
                    
                    # Vérifier si c'est une action d'appel
                    if data.get('action') == 'compose' and 'from' in data and 'to' in data:
                        source = str(data['from'])
                        destination = str(data['to'])
                        
                        logger.info(f"Demande d'appel reçue: {source} -> {destination}")
                        if self.print_log:
                            print(f"Demande d'appel reçue: {source} -> {destination}")
                        
                        # Lancer l'appel dans un thread séparé pour ne pas bloquer
                        import threading
                        call_thread = threading.Thread(
                            target=self.place_call,
                            args=(source, destination)
                        )
                        call_thread.daemon = True
                        call_thread.start()
                        
                        # Envoyer confirmation sur MQTT
                        self.send_mqtt_message({
                            "type": "CALL_INITIATED",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "source": source,
                            "destination": destination,
                            "status": "pending"
                        })
                    else:
                        logger.warning(f"Format de message de pilotage non reconnu: {payload_str}")
                
                except json.JSONDecodeError:
                    logger.error(f"Erreur de décodage JSON du message de pilotage: {payload_str}")
        
        except Exception as e:
            logger.error(f"Erreur dans le traitement du message MQTT: {e}")            
    
    def send_mqtt_message(self, message):
        """Envoie un message via MQTT"""
        if not self.mqtt_client:
            return False
        
        try:
            # Supprimer les données binaires
            if isinstance(message, dict):
                # Convertir les données binaires en hexadécimal
                clean_message = {}
                for k, v in message.items():
                    if isinstance(v, bytes):
                        clean_message[k] = self.bytes_to_hex(v)
                    else:
                        clean_message[k] = v
                
                payload = json.dumps(clean_message)
                self.mqtt_client.publish(self.MQTT_TOPIC, payload)
                logger.debug(f"Message MQTT envoyé: {self.MQTT_TOPIC}")
                return True
        except Exception as e:
            logger.error(f"Erreur envoi MQTT: {e}")
        return False

    def send_call_history_mqtt(self, call):
        """
        Envoie l'historique complet de l'appel en JSON sur MQTT.
        Version améliorée avec plus d'informations.
        """
        data = {
            "type": "CALL_HISTORY",
            "call_id": call["call_id"],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "calling_number": call.get("calling_number", "unknown"),
            "caller_name": call.get("caller_name", "unknown"),
            "called_number": call.get("called_number", "unknown"),
            "called_extension": call.get("called_extension", "unknown"),
            "direction": call.get("direction", "unknown"),
            "start_time": call.get("start_time", "unknown"),
            "end_time": call.get("end_time", "unknown"),
            "duration": call.get("duration", 0),
            "status": call.get("status", "unknown"),
            "events": []
        }
        
        # Ajouter tous les événements
        for ev in call["events"]:
            data["events"].append({
                "timestamp": ev.get("timestamp", ""),
                "type": ev.get("type", ""),
                "description": ev.get("description", "")
            })
        
        # Ajouter des informations sur les transferts si disponibles
        if any("transfer" in key for key in call.keys()):
            data["transfer_info"] = {}
            for key, value in call.items():
                if "transfer" in key:
                    data["transfer_info"][key] = value
        
        # Ajouter des informations sur les mises en attente si disponibles
        if "hold_time" in call:
            data["hold_info"] = {
                "hold_time": call.get("hold_time"),
                "retrieve_time": call.get("retrieve_time", "unknown"),
                "hold_duration": call.get("last_hold_duration", 0)
            }
        
        # Publier sur MQTT avec un topic spécifique pour les historiques
        mqtt_topic = f"{self.MQTT_TOPIC}/history"
        payload = json.dumps(data, ensure_ascii=False)
        
        try:
            self.mqtt_client.publish(mqtt_topic, payload)
            logger.info(f"Historique d'appel ID {call['call_id']} publié sur MQTT: {mqtt_topic}")
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de l'historique sur MQTT: {e}")

    # À ajouter après initialisation du client MQTT
    def test_mqtt_call(self):
        """Fonction de test pour déclencher un appel via MQTT"""
        test_message = {
            "action": "test",
            "type": "connexion"
        }
        try:
            mqtt_topic = f"{self.MQTT_TOPIC}/pilote"
            payload = json.dumps(test_message)
            result = self.mqtt_client.publish(mqtt_topic, payload)
            logger.info(f"Test MQTT d'appel envoyé: {result.rc} - Message: {payload}")
            if self.print_log:
                print(f"Test MQTT d'appel envoyé sur {mqtt_topic}: {payload}")
            return result.rc == 0
        except Exception as e:
            logger.error(f"Erreur lors du test MQTT: {e}")
            return False
    # --- Utilitaires Hex/ASCII ---
    def bytes_to_hex(self, data):
        """Convertit les données binaires en chaîne hexadécimale"""
        if not data:
            return ""
        return ' '.join(f"{b:02X}" for b in data)
    
    def hex_to_bytes(self, hex_str):
        """Convertit une chaîne hexadécimale en données binaires"""
        return binascii.unhexlify(hex_str.replace(" ", ""))
    
    # --- Commandes CSTA ---
    def build_start_monitor_cmd(self, device):
        """Crée une commande pour commencer la surveillance d'un appareil"""
        ascii_device = " ".join(f"{ord(c):02X}" for c in device)
        cmd = f"00 11 A1 0F 02 01 01 02 01 47 30 07 80 05 {ascii_device}"
        return self.hex_to_bytes(cmd)

    def build_stop_monitor_cmd(self, device):
        """Crée une commande pour arrêter la surveillance d'un appareil"""
        ascii_device = " ".join(f"{ord(c):02X}" for c in device)
        invoke_id = self.last_invoke_id
        self.last_invoke_id = (self.last_invoke_id + 1) % 0xFFFF
        
        id_hi = (invoke_id >> 8) & 0xFF
        id_lo = invoke_id & 0xFF
        cmd = f"00 13 A1 11 02 02 {id_hi:02X} {id_lo:02X} 02 01 48 30 07 80 05 {ascii_device}"
        return self.hex_to_bytes(cmd)    
    
    def build_snapshot_cmd(self, device):
        """Crée une commande pour obtenir un snapshot de l'état d'un appareil"""
        ascii_device = " ".join(f"{ord(c):02X}" for c in device)
        cmd = f"00 0F A1 0D 02 01 03 02 01 4A 80 05 {ascii_device}"
        return self.hex_to_bytes(cmd)
    
    def build_keepalive_cmd(self):
        """Crée une commande keepalive"""
        invoke_id = self.last_invoke_id
        self.last_invoke_id = (self.last_invoke_id + 1) % 0xFFFF
        
        id_hi = (invoke_id >> 8) & 0xFF
        id_lo = invoke_id & 0xFF
        cmd = f"00 0C A1 0A 02 02 {id_hi:02X} {id_lo:02X} 02 01 34 0A 01 02"
        return self.hex_to_bytes(cmd)
    
    def prepare_keepalive_response(self, received_data):
        """Prépare une réponse à un keepalive"""
        hex_data = self.bytes_to_hex(received_data)
        
        # Chercher "02 01 34 05"
        idx = hex_data.find("02 01 34 05")
        if idx != -1 and idx + 11 <= len(hex_data):
            kid = hex_data[idx+9:idx+11]
            response = self.hex_to_bytes(f"00 0D A2 0B 02 02 00 00 30 05 02 01 34 05 {kid}")
            return response
        return None
        
    def identify_message_type(self, hex_data):
        """Identifie le type de message CSTA"""
        # Message d'entretien (keepalive)
        if hex_data.startswith("00 0C A1"):
            return "KEEPALIVE_REQUEST"
            
        # Réponse à un keepalive
        if hex_data.startswith("00 0C A2") and "02 01 34 05" in hex_data:
            return "KEEPALIVE_RESPONSE"
            
        # Réponse à un StartMonitor
        if hex_data.startswith("00") and "A2" in hex_data[:10] and "02 01 47" in hex_data:
            return "START_MONITOR_RESPONSE"
            
        # Réponse à un Snapshot
        if hex_data.startswith("00") and "A2" in hex_data[:10] and "02 01 4A" in hex_data:
            return "SNAPSHOT_RESPONSE"
            
        # Événement de transfert (structure spécifique avec AD 2F)
        if "02 01 15" in hex_data and ("AD 2F" in hex_data or "AD 59" in hex_data or "AD 61" in hex_data):
            return "CALL_EVENT"  # Sera identifié comme TRANSFERRED dans decode_csta_event
            
        # Événement (appel, transfert, etc.)
        if "02 01" in hex_data and any(pattern in hex_data for pattern in 
                                    ["02 01 01", "02 01 03", "02 01 04", "02 01 06", 
                                        "02 01 0B", "02 01 0C", "02 01 0E", "02 01 0F", "02 01 15"]):
            return "CALL_EVENT"
            
        # Par défaut
        return "UNKNOWN_MESSAGE"

    def decode_csta_event(self, hex_data):
        """Décode un événement CSTA à partir du format hexadécimal"""
        result = {
            "type": "UNKNOWN_EVENT",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Initialisation des variables potentiellement utilisées avant d'être définies
        calling_device = None
        called_device = None
        device = None
        
        # Vérifier le type d'événement (après 02 01)
        idx = hex_data.find("02 01")
        if idx != -1 and idx + 8 <= len(hex_data):
            try:
                event_code = int(hex_data[idx+6:idx+8], 16)
                
                # Correspondance des codes d'événements
                event_types = {
                    0x01: "CALL_CLEARED",
                    0x03: "DELIVERED",
                    0x04: "ESTABLISHED",
                    0x06: "HELD",
                    0x0B: "RETRIEVED",
                    0x0C: "CONFERENCED",
                    0x0E: "DIVERTED",
                    0x0F: "TRANSFERRED",
                    0x15: "SERVICE_INITIATED",
                        # Peut aussi être d'autres événements
                }
                
                # Déterminer le type plus précis pour le code 0x15
                if event_code == 0x15:
                    # Amélioration de la détection des patterns
                    if "A5 40" in hex_data or "A5 45" in hex_data:
                        result["type"] = "ESTABLISHED"
                    elif "A5 3F" in hex_data:
                        result["type"] = "ESTABLISHED"
                    elif "A5" in hex_data[:60]:
                        result["type"] = "ESTABLISHED"
                    elif "A3 33" in hex_data or "A3 30" in hex_data:
                        result["type"] = "CONNECTED"
                    elif "AD 59" in hex_data or "AD 53" in hex_data or "AD 61" in hex_data:
                        result["type"] = "TRANSFERRED"
                    elif "0A 01 1C" in hex_data:  # Code de cause de transfert immédiat
                        result["type"] = "CALL_FORWARDED"
                        
                        # Extraction des devices
                        idx_source = hex_data.find("63 07 84 05")
                        idx_destination = hex_data.find("63 07 84 05", idx_source + 1)
                        
                        if idx_source != -1:
                            result["device"] = self.extract_ascii(hex_data, idx_source + 12)
                        
                        if idx_destination != -1:
                            result["diverted_to_device"] = self.extract_ascii(hex_data, idx_destination + 12)
                        
                        # Informations supplémentaires sur le renvoi
                        result["forward_type"] = "immediate"                    
                    elif "A7 1D" in hex_data or "A7" in hex_data[:50]:
                        result["type"] = "DELIVERED"
                    elif "A9 2C" in hex_data or "A9 26" in hex_data:
                        result["type"] = "ORIGINATED"
                    elif "AB 1A" in hex_data or "AB" in hex_data[:50]:
                        result["type"] = "RETRIEVED"
                    elif "4E 01 06" in hex_data:
                        result["type"] = "FAILED"
                    elif "A2 1D" in hex_data or "A2" in hex_data[:50]:
                        result["type"] = "CALL_CLEARED"
                    elif "AC 11" in hex_data or "AC" in hex_data[:50]:
                        result["type"] = "SERVICE_INITIATED"
                    else:
                        # Recherche d'indices supplémentaires
                        if "63 0" in hex_data and "61 0" in hex_data and "62 0" in hex_data:
                            # Motif typique d'un événement ESTABLISHED avec numéros appelant et appelé
                            result["type"] = "ESTABLISHED"
                        elif "63 0" in hex_data and "4E 01 03" in hex_data:
                            # Combinaison typique d'un device et d'un état connecté
                            result["type"] = "ESTABLISHED"
                        else:
                            result["type"] = "SERVICE_INITIATED"
                elif event_code in event_types:
                    result["type"] = event_types[event_code]
                else:
                    result["type"] = f"UNKNOWN_EVENT_{event_code:02X}"
                    
                result["event_code"] = event_code
            except ValueError:
                pass
        
        # Extraire l'ID d'invocation
        idx = hex_data.find("02 02")
        if idx != -1 and idx + 14 <= len(hex_data):
            try:
                invoke_hex = hex_data[idx+6:idx+14].replace(" ", "")
                result["invoke_id"] = int(invoke_hex, 16)
            except ValueError:
                pass
        
        # Extraire le CrossRefIdentifier (après 55 04 01)
        idx = hex_data.find("55 04 01")
        if idx != -1 and idx + 14 <= len(hex_data):
            try:
                xref_hex = hex_data[idx+9:idx+14].replace(" ", "")
                result["cross_ref_id"] = int(xref_hex, 16)
            except ValueError:
                pass
        
        # Extraire l'ID d'appel (après 82 02)
        idx = hex_data.find("82 02")
        if idx != -1 and idx + 14 <= len(hex_data):
            try:
                call_hex = hex_data[idx+6:idx+14].replace(" ", "")
                result["call_id"] = int(call_hex, 16)
            except ValueError:
                pass
        
        # Extraire les devices impliqués selon le type d'événement
        
        # 1. CallingDevice (61 07 84 05 ou 61 0D 82 0B - pour les numéros plus longs)
        for pattern in ["61 07 84 05", "61 0D 82 0B"]:
            idx = hex_data.find(pattern)
            if idx != -1:
                device = self.extract_ascii(hex_data, idx+12)
                if device:
                    result["calling_device"] = device
                break
        
        # 2. CalledDevice (62 07 84 05 ou 62 0D 82 0B - pour les numéros plus longs)
        for pattern in ["62 07 84 05", "62 0D 82 0B"]:
            idx = hex_data.find(pattern)
            if idx != -1:
                device = self.extract_ascii(hex_data, idx+12)
                if device:
                    result["called_device"] = device
                break
        
        # 3. ConnectionDevice/HoldingDevice/etc. (63 07 84 05 ou 63 0E 82 0C - pour les numéros plus longs)
        for pattern in ["63 07 84 05", "63 0E 82 0C"]:
            idx = hex_data.find(pattern)
            if idx != -1:
                device = self.extract_ascii(hex_data, idx+12)
                if device:
                    if result["type"] == "HELD":
                        result["holding_device"] = device
                    elif result["type"] == "RETRIEVED":
                        result["retrieving_device"] = device
                    elif result["type"] == "TRANSFERRED":
                        result["transferring_device"] = device
                    else:
                        result["device"] = device
                break
        
        # 4. Devices supplémentaires (selon le type)
        if result["type"] == "TRANSFERRED":
            # Transferred to device - chercher après A3 dans les sections de connexion
            connection_sections = []
            pos = 0
            while True:
                idx = hex_data.find("A3", pos)
                if idx == -1 or idx + 20 > len(hex_data):
                    break
                connection_sections.append(idx)
                pos = idx + 3
            
            # Parcourir les sections de connexion pour trouver les devices associés
            for section_idx in connection_sections:
                # Chercher les sections avec pattern 80 XX (identifiant de longueur variable)
                for pattern in ["80 05", "80 0B", "80 0C"]:
                    idx = hex_data.find(pattern, section_idx, section_idx + 50)
                    if idx != -1:
                        device = self.extract_ascii(hex_data, idx+6)
                        if device and device not in [result.get("transferring_device"), result.get("device")]:
                            result["transferred_to_device"] = device
                            break
        
        elif result["type"] == "DIVERTED":
            # Diverted to device (66 07 84 05)
            idx = hex_data.find("66 07 84 05")
            if idx != -1:
                device = self.extract_ascii(hex_data, idx+12)
                if device:
                    result["diverted_to_device"] = device
                    
            # Diversion type (67 01)
            idx = hex_data.find("67 01")
            if idx != -1:
                try:
                    div_type = int(hex_data[idx+6:idx+8], 16)
                    result["diversion_type_code"] = div_type
                    diversion_types = {
                        0: "forward-immediate",
                        1: "forward-busy",
                        2: "forward-no-answer",
                        3: "deflect"
                    }
                    result["diversion_type"] = diversion_types.get(div_type, f"unknown({div_type})")
                except ValueError:
                    pass
        
        elif result["type"] == "CONFERENCED":
            # Conference ID (C1 05)
            idx = hex_data.find("C1 05")
            if idx != -1:
                try:
                    conf_hex = hex_data[idx+6:idx+16].replace(" ", "")
                    result["conference_id"] = int(conf_hex, 16)
                except ValueError:
                    pass
        
        # État de connexion (4E 01)
        # État de connexion (4E 01)
        idx = hex_data.find("4E 01")
        if idx != -1 and idx + 8 <= len(hex_data):
            try:
                state = int(hex_data[idx+6:idx+8], 16)
                result["connection_state"] = state
                
                # Map des états de connexion
                conn_states = {
                    0: "null",
                    1: "initiated",
                    2: "alerting",
                    3: "connected",
                    4: "hold",
                    5: "queued",
                    6: "fail",
                    7: "busy",
                    8: "call_delivered",
                    9: "call_received",
                    10: "forwarded",
                    11: "conferenced",
                    12: "dialing",
                    13: "ringing",
                    14: "suspended",
                    15: "blocked",
                    16: "parked"
                }
                result["connection_state_desc"] = conn_states.get(state, f"unknown({state})")
            except ValueError:
                pass

        # Code de cause (0A 01)
        idx = hex_data.find("0A 01")
        if idx != -1 and idx + 8 <= len(hex_data):
            try:
                cause = int(hex_data[idx+6:idx+8], 16)
                result["cause_code"] = cause
                
                # Map des codes de cause
                causes = {
                    0x00: "unspecified",
                    0x16: "newCall",
                    0x1C: "callForwardImmediate",
                    0x22: "normal",
                    0x28: "facilityIE",
                    0x30: "normalClearing",
                    0x0B: "callPickup",
                    0x0D: "destNotObtainable",
                    0x25: "consultation",
                    0x2E: "networkSignal",
                    0x03: "newConnection",
                    0x20: "busy",
                    0x24: "callForwardBusy",
                    0x26: "callForwardNoReply",
                    0x2A: "invalidNumber",
                    0x2C: "networkCongestion",
                    0x32: "temporaryFailure",
                    0x34: "resourceUnavailable"
                }
                result["cause"] = causes.get(cause, f"unknown({cause:02X})")
            except ValueError:
                pass
        




        # Timestamp - souvent après 17 0D
        idx = hex_data.find("17 0D")
        if idx != -1 and idx + 39 <= len(hex_data):
            try:
                # Extraire les 12 caractères de date/heure (format YYMMDDhhmmss)
                timestamp_ascii = ""
                for i in range(idx+6, idx+6+36, 3):
                    if i+2 <= len(hex_data):
                        byte_hex = hex_data[i:i+2]
                        if byte_hex.isalnum():
                            byte_val = int(byte_hex, 16)
                            if 48 <= byte_val <= 57 or 65 <= byte_val <= 90 or 97 <= byte_val <= 122:
                                timestamp_ascii += chr(byte_val)
                
                if len(timestamp_ascii) >= 12:
                    # Format: YYMMDDhhmmss
                    yy = timestamp_ascii[0:2]
                    mm = timestamp_ascii[2:4]
                    dd = timestamp_ascii[4:6]
                    hh = timestamp_ascii[6:8]
                    mn = timestamp_ascii[8:10]
                    ss = timestamp_ascii[10:12]
                    
                    result["csta_timestamp"] = f"20{yy}-{mm}-{dd} {hh}:{mn}:{ss}"
            except (ValueError, IndexError):
                pass
        
        # Créer description textuelle de l'événement

        description = self.create_event_description(result)
        if description:
            result["description"] = description
            
            return result
    
    def extract_ascii(self, hex_data, start_idx, max_length=20):
        """Extrait une chaîne ASCII à partir d'un index dans des données hex"""
        result = ""
        hex_bytes = hex_data[start_idx:].split()
        
        for i, byte_hex in enumerate(hex_bytes):
            if i >= max_length:
                break
                
            try:
                byte_val = int(byte_hex, 16)
                # Pour les identifiants de périphériques, on cherche généralement des chiffres (0-9)
                if 48 <= byte_val <= 57:  # Chiffres ASCII '0' à '9'
                    result += chr(byte_val)
                else:
                    # Si on a déjà commencé à collecter des chiffres et qu'on trouve autre chose, on arrête
                    if result:
                        break
            except ValueError:
                break
        
        return result.strip()
    
    def create_event_description(self, event):
        """
        Crée une description textuelle de l'événement CSTA.
        Prend un dictionnaire d'événement et retourne une description en français.
        """
        if not event or not isinstance(event, dict):
            return None
            
        event_type = event.get("type", "UNKNOWN")
        
        # Dictionnaire de fonctions de formatage par type d'événement
        formatters = {
            "CALL_CLEARED": self._format_call_cleared,
            "DELIVERED": self._format_delivered,
            "ESTABLISHED": self._format_established,
            "HELD": self._format_held,
            "RETRIEVED": self._format_retrieved,
            "CONFERENCED": self._format_conferenced,
            "DIVERTED": self._format_diverted,
            "TRANSFERRED": self._format_transferred,
            "NEW_CALL": self._format_new_call,
            "SERVICE_INITIATED": self._format_service_initiated,
            "CONNECTED": self._format_connected,
            "FAILED": self._format_failed,
            "ORIGINATED": self._format_originated
        }
        
        # Obtenir la fonction de formatage appropriée ou une fonction par défaut
        formatter = formatters.get(event_type, lambda e: f"Événement {event_type}")
     # Vérifier si formatter existe avant de l'appeler
        if formatter:
            try:
                return formatter(event)
            except Exception as e:
                # Gérer les erreurs dans les formateurs
                logger.error(f"Erreur lors du formatage de l'événement {event_type}: {e}")
                return f"Événement {event_type} (erreur de formatage)"
        else:
            return f"Événement {event_type}"       
        # Appliquer la fonction de formatage
        #return formatter(event)

    def make_call_csta(self, source_extension, destination_number):
        """
        Établit une connexion au PABX et exécute les commandes pour passer un appel.
        
        :param source_extension: Le numéro du poste source
        :param destination_number: Le numéro à appeler
        :return: True si la séquence d'appel a été exécutée avec succès, False sinon
        """
        try:
            # Créer et connecter le socket
            call_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            call_sock.settimeout(10)
            
            logger.info(f"Connexion au PABX pour appel de {source_extension} vers {destination_number}...")
            if self.print_log:
                print(f"Connexion au PABX pour appel de {source_extension} vers {destination_number}...")
            
            call_sock.connect((self.PABX_IP, self.PABX_PORT))
            
            # Séquence d'initialisation
            # 1. Identification
            ident_cmd = b"\x42"
            call_sock.sendall(ident_cmd)
            response = call_sock.recv(1024)
            logger.info(f"Réponse d'identification pour appel: {self.bytes_to_hex(response)}")
            time.sleep(1)
            
            # 2. Établissement de la session
            session_cmd = self.hex_to_bytes(
                "00 46 60 44 80 02 07 80 A1 07 06 05 2B 0C 00 81 34 BE 35 "
                "28 33 06 07 2B 0C 00 81 5A 81 48 A0 28 30 26 03 02 03 C0 "
                "30 16 80 04 03 E7 B6 48 81 06 02 5F FD 03 FE A0 83 02 06 "
                "C0 84 02 03 F0 30 08 82 02 03 D8 83 02 06 C0"
            )
            call_sock.sendall(session_cmd)
            response = call_sock.recv(1024)
            logger.info(f"Session établie pour appel: {self.bytes_to_hex(response)}")
            time.sleep(1)
            
            # 3. Générer et envoyer les commandes d'appel
            commands = self.make_call_csta(source_extension, destination_number)
            
            # 3.1 Envoyer Make Call (appel fictif)
            call_sock.sendall(commands[0])
            response = call_sock.recv(1024)
            logger.info(f"Réponse MakeCall (fictif): {self.bytes_to_hex(response)}")
            time.sleep(1)
            
            # 3.2 Envoyer Generate Digits
            call_sock.sendall(commands[1])
            response = call_sock.recv(1024)
            logger.info(f"Réponse GenerateDigits: {self.bytes_to_hex(response)}")
            time.sleep(1)
            
            # 3.3 Envoyer Clear Connection (pour terminer l'appel fictif)
            clear_conn_cmd = self.hex_to_bytes(f"00 13 A1 11 02 01 03 02 01 34 30 09 80 05 {self.to_ascii_hex(source_extension)} 81 00")
            call_sock.sendall(clear_conn_cmd)
            response = call_sock.recv(1024)
            logger.info(f"Réponse ClearConnection: {self.bytes_to_hex(response)}")
            time.sleep(1)
            
            # 3.4 Envoyer Make Call (avec le vrai numéro)
            real_call_cmd = self.hex_to_bytes(f"00 1D A1 1B 02 01 04 02 01 32 30 13 80 05 {self.to_ascii_hex(source_extension)} 81 05 {self.to_ascii_hex(destination_number)} 82 01 01")
            call_sock.sendall(real_call_cmd)
            response = call_sock.recv(1024)
            logger.info(f"Réponse MakeCall (réel): {self.bytes_to_hex(response)}")
            
            # 4. Fermer la connexion
            call_sock.close()
            
            logger.info(f"Appel initié avec succès: {source_extension} -> {destination_number}")
            if self.print_log:
                print(f"Appel initié avec succès: {source_extension} -> {destination_number}")
            
            return True
        
        except Exception as e:
            logger.error(f"Erreur lors de l'initiation de l'appel: {e}")
            if self.print_log:
                print(f"Erreur lors de l'initiation de l'appel: {e}")
            return False
        
        finally:
            if 'call_sock' in locals() and call_sock:
                try:
                    call_sock.close()
                except:
                    pass

    def to_ascii_hex(self, s):
        return ' '.join(f"{ord(c):02X}" for c in s)



    # Fonctions de formatage individuelles pour chaque type d'événement
    def _format_call_cleared(self, event):
        device = event.get("device", "?")
        cause = event.get("cause", "normal")
        return f"Appel terminé par {device}, cause: {cause}"

    def _format_delivered(self, event):
        called_device = event.get("called_device", "?")
        calling_device = event.get("calling_device", "?")
        return f"Appel sonnant de {calling_device} vers {called_device}"

    def _format_established(self, event):
        device = event.get("device", "?")
        called_device = event.get("called_device", "?")
        calling_device = event.get("calling_device", "?")
        if device != "?":
            return f"Communication établie entre {calling_device} et {called_device}"
        else:
            return f"Communication établie entre {calling_device} et {called_device}"

    def _format_held(self, event):
        holding_device = event.get("holding_device", event.get("device", "?"))
        return f"Appel mis en garde par {holding_device}"

    def _format_retrieved(self, event):
        retrieving_device = event.get("retrieving_device", event.get("device", "?"))
        return f"Appel repris de garde par {retrieving_device}"

    def _format_conferenced(self, event):
        device = event.get("device", "?")
        conf_id = event.get("conference_id", "?")
        return f"Conférence établie par {device}, ID: {conf_id}"

    def _format_diverted(self, event):
        device = event.get("device", "?")
        diverted_device = event.get("diverted_to_device", "?")
        div_type = event.get("diversion_type", "?")
        return f"Appel dévié de {device} vers {diverted_device}, type: {div_type}"

    def _format_transferred(self, event):
        from_device = event.get("transferring_device", event.get("device", "?"))
        to_device = event.get("transferred_to_device", "?")
        return f"Appel transféré de {from_device} vers {to_device}"

    def _format_new_call(self, event):
        calling_device = event.get("calling_device", "?")
        called_device = event.get("called_device", "?")
        return f"Nouvel appel de {calling_device} vers {called_device}"

    def _format_service_initiated(self, event):
        device = event.get("device", "?")
        return f"Service initié par {device}"

    def _format_connected(self, event):
        device = event.get("device", "?")
        return f"Connexion établie pour {device}"

    def _format_failed(self, event):
        device = event.get("device", "?")
        cause = event.get("cause", "unknown")
        return f"Échec de l'appel pour {device}, cause: {cause}"
        
    def _format_originated(self, event):
        device = event.get("device", "?")
        called_device = event.get("called_device", "?")
        return f"Appel sortant initié par {device} vers {called_device}"

    def create_event_description2(self, event):
        """Crée une description textuelle de l'événement"""
        event_type = event.get("type", "")
        
        if event_type == "CALL_CLEARED":
            device = event.get("device", "?")
            cause = event.get("cause", "normal")
            return f"Appel terminé par {device}, cause: {cause}"
            
        elif event_type == "DELIVERED":
            called_device = event.get("called_device", "?")
            calling_device = event.get("calling_device", "?")
            return f"Appel sonnant de {calling_device} vers {called_device}"
            
        elif event_type == "ESTABLISHED":
            device = event.get("device", "?") 
            called_device = event.get("called_device", "?")
            calling_device = event.get("calling_device", "?")
            return f"Communication établie entre {device} et {calling_device} vers {called_device}"
            #return f"Communication établie entre {device} et {calling_device}"
            
        elif event_type == "HELD":
            holding_device = event.get("holding_device", "?")
            return f"Appel mis en garde par {holding_device}"
            
        elif event_type == "RETRIEVED":
            retrieving_device = event.get("retrieving_device", "?")
            return f"Appel repris de garde par {retrieving_device}"
            
        elif event_type == "CONFERENCED":
            device = event.get("device", "?")
            conf_id = event.get("conference_id", "?")
            return f"Conférence établie par {device}, ID: {conf_id}"
            
        elif event_type == "DIVERTED":
            device = event.get("device", "?")
            diverted_device = event.get("diverted_to_device", "?")
            div_type = event.get("diversion_type", "?")
            return f"Appel dévié de {device} vers {diverted_device}, type: {div_type}"
            
        elif event_type == "TRANSFERRED":
            from_device = event.get("transferring_device", "?")
            to_device = event.get("transferred_to_device", "?")
            return f"Appel transféré de {from_device} vers {to_device}"
            
        elif event_type == "NEW_CALL":
            calling_device = event.get("calling_device", "?")
            called_device = event.get("called_device", "?")
            return f"Nouvel appel de {calling_device} vers {called_device}"
            
        elif event_type == "SERVICE_INITIATED":
            device = event.get("device", "?")
            return f"Service initié par {device}"
            
        elif event_type == "CONNECTED":
            device = event.get("device", "?")
            return f"Connexion établie pour {device}"
            
        elif event_type == "FAILED":
            device = event.get("device", "?")
            cause = event.get("cause", "unknown")
            return f"Échec de l'appel pour {device}, cause: {cause}"
            
        return None
    
    def decode_snapshot_response(self, hex_data, device):
        """Décode la réponse d'un snapshot CSTA"""
        result = {
            "type": "SNAPSHOT_RESPONSE",
            "device": device,
            #"raw_data": hex_data,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "decoded": {
                "message_type": "Unknown",
                "invoke_id": None,
                "result_code": None,
                "device_id": None,
                "device_info": {}
            }
        }
        
        # Vérifier le type de message (A2 pour les réponses)
        if "A2" in hex_data[:10]:
            result["decoded"]["message_type"] = "Response"
        
        # Extraire l'invoke ID (après 02 01)
        idx = hex_data.find("02 01")
        if idx != -1 and idx + 8 <= len(hex_data):
            try:
                invoke_id = int(hex_data[idx+6:idx+8], 16)
                result["decoded"]["invoke_id"] = invoke_id
            except ValueError:
                pass
        
        # Extraire le code résultat (généralement après 02 01 XX 30)
        idx = hex_data.find("30", idx+8)
        if idx != -1 and idx + 12 <= len(hex_data):
            next_idx = hex_data.find("02 01", idx)
            if next_idx != -1 and next_idx + 8 <= len(hex_data):
                try:
                    result_code = int(hex_data[next_idx+6:next_idx+8], 16)
                    result["decoded"]["result_code"] = result_code
                    # 47 hex (71 décimal) indique généralement un succès
                    if result_code == 71:
                        result["decoded"]["result"] = "Success"
                    else:
                        result["decoded"]["result"] = f"Failure (code {result_code})"
                except ValueError:
                    pass
        
        # Extraire l'ID du périphérique (généralement après 55 04 01)
        idx = hex_data.find("55 04 01")
        if idx != -1 and idx + 14 <= len(hex_data):
            try:
                # Lire les 4 caractères après 55 04 01
                device_id_hex = hex_data[idx+9:idx+14].replace(" ", "")
                if len(device_id_hex) >= 4:
                    device_id = int(device_id_hex, 16)
                    result["decoded"]["device_id"] = device_id
            except ValueError:
                pass
        
        # Extraire les informations sur le périphérique
        # Media Class (80 03 02 80 00 pour Voice)
        idx = hex_data.find("80 03")
        if idx != -1 and idx + 14 <= len(hex_data):
            media_class_hex = hex_data[idx+6:idx+14].replace(" ", "")
            if "028000" in media_class_hex:
                result["decoded"]["device_info"]["media_class"] = "Voice"
            elif "028001" in media_class_hex:
                result["decoded"]["device_info"]["media_class"] = "Data"
            else:
                result["decoded"]["device_info"]["media_class"] = f"Unknown ({media_class_hex})"
        
        # Device Type (81 02)
        idx = hex_data.find("81 02")
        if idx != -1 and idx + 11 <= len(hex_data):
            try:
                type_hex = hex_data[idx+6:idx+11].replace(" ", "")
                type_val = int(type_hex, 16)
                result["decoded"]["device_info"]["device_type"] = type_val
            except ValueError:
                pass
        
        # Device Instance (82 02)
        idx = hex_data.find("82 02")
        if idx != -1 and idx + 11 <= len(hex_data):
            try:
                instance_hex = hex_data[idx+6:idx+11].replace(" ", "")
                instance_val = int(instance_hex, 16)
                result["decoded"]["device_info"]["device_instance"] = instance_val
            except ValueError:
                pass
        
        # Device Category (83 02)
        idx = hex_data.find("83 02")
        if idx != -1 and idx + 11 <= len(hex_data):
            try:
                category_hex = hex_data[idx+6:idx+11].replace(" ", "")
                category_val = int(category_hex, 16)
                result["decoded"]["device_info"]["device_category"] = category_val
            except ValueError:
                pass
        
        # Device Model (85 02)
        idx = hex_data.find("85 02")
        if idx != -1 and idx + 11 <= len(hex_data):
            try:
                model_hex = hex_data[idx+6:idx+11].replace(" ", "")
                model_val = int(model_hex, 16)
                result["decoded"]["device_info"]["device_model"] = model_val
                
                # Correspondance des modèles Alcatel courants
                model_map = {
                    366: "Alcatel IP Touch 4028",
                    365: "Alcatel IP Touch 4018",
                    364: "Alcatel IP Touch 4008",
                    366: "Alcatel ALE 20"
                }
                if model_val in model_map:
                    result["decoded"]["device_info"]["model_name"] = model_map[model_val]
            except ValueError:
                pass
        
        # Indicateur supplémentaire (84 01)
        idx = hex_data.find("84 01")
        if idx != -1 and idx + 8 <= len(hex_data):
            try:
                indicator = int(hex_data[idx+6:idx+8], 16)
                result["decoded"]["device_info"]["additional_indicator"] = indicator
            except ValueError:
                pass
        
        return result

    def update_call_history(self, event_info):
        """Met à jour l'historique d'un appel avec un nouvel événement"""
        if not event_info:
            return
        
        # Obtenir l'ID de l'appel (call_id ou cross_ref_id)
        call_id = event_info.get("call_id") or event_info.get("cross_ref_id")
        if not call_id:
            return  # Impossible de suivre sans ID d'appel
        
        # Timestamp actuel
        timestamp = event_info.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Créer ou récupérer l'enregistrement d'appel
        if call_id not in self.active_calls:
            # Nouvel appel
            self.active_calls[call_id] = {
                "call_id": call_id,
                "start_time": timestamp,
                "events": [],
                "status": "initiated"
            }
        
        # Récupérer l'appel en cours
        call = self.active_calls[call_id]
        
        # Ajouter l'événement à l'historique
        call["events"].append({
            "timestamp": timestamp,
            "type": event_info.get("type", "UNKNOWN"),
            "description": event_info.get("description", "")
        })
        
        # Mettre à jour les informations sur l'appel selon le type d'événement
        event_type = event_info.get("type", "")
        
        # Numéros appelant et appelé
        if "calling_device" in event_info and not call.get("calling_number"):
            call["calling_number"] = event_info["calling_device"]
        
        if "called_device" in event_info and not call.get("called_number"):
            call["called_number"] = event_info["called_device"]
        
        # Extension interne si présente
        if "device" in event_info:
            if event_info["device"] in self.DEVICES_TO_MONITOR:
                call["called_extension"] = event_info["device"]
                call["direction"] = "entrant"
            elif "calling_device" in event_info and event_info["calling_device"] in self.DEVICES_TO_MONITOR:
                call["calling_extension"] = event_info["calling_device"]
                call["direction"] = "sortant"
        
        # Gestion spécifique pour les événements ORIGINATED
        if event_type == "ORIGINATED":
            call["direction"] = "sortant"
        
        # Traiter les différents types d'événements
        if event_type == "CALL_CLEARED":
            call["status"] = "terminated"
            call["end_time"] = timestamp
            
            # Calculer la durée si possible
            if "start_time" in call:
                try:
                    start = datetime.strptime(call["start_time"], "%Y-%m-%d %H:%M:%S")
                    end = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                    call["duration"] = (end - start).total_seconds()
                except Exception as e:
                    logger.error(f"Erreur de calcul de durée: {e}")
                    call["duration"] = 0
            
            # Journaliser et envoyer l'historique complet uniquement si la durée est > 0
            if call.get("duration", 0) > 0:
                self.log_call_history(call)
                self.send_call_history_mqtt(call)
            
            # Nettoyer l'appel terminé
            del self.active_calls[call_id]
        
        # ... (reste du code existant)
        
        return call
            
            # --- Connexion et surveillance ---

    def run(self):
        """Fonction principale exécutant la surveillance"""
        logger.info(f"Démarrage de la surveillance CSTA pour les postes: {', '.join(self.DEVICES_TO_MONITOR)}")
        if self.print_log:
            print(f"Démarrage de la surveillance CSTA pour les postes: {', '.join(self.DEVICES_TO_MONITOR)}")
        
        # Initialiser MQTT au lancement du programme
        self.mqtt_client = self.init_mqtt()
        if self.mqtt_client:
            logger.info("Client MQTT initialisé avec succès")
            if self.print_log:
                print("Client MQTT initialisé avec succès")
            
            # Faire un test après quelques secondes
            time.sleep(3)
            self.test_mqtt_call()
        else:
            logger.error("Échec de l'initialisation MQTT. Les notifications MQTT ne seront pas envoyées.")
            if self.print_log:
                print("Échec de l'initialisation MQTT. Les notifications MQTT ne seront pas envoyées.")
        
        while True:
            try:
                # Rétablir MQTT si déconnecté
                if not self.mqtt_client:
                    self.mqtt_client = self.init_mqtt()
                
                # Établir la connexion au PABX
                connection_result = self.connect_and_monitor()
                
                if connection_result:
                    logger.info(f"Session terminée normalement, reconnexion dans {self.RECONNECT_DELAY} secondes")
                    if self.print_log:
                        print(f"Session terminée normalement, reconnexion dans {self.RECONNECT_DELAY} secondes")
                else:
                    logger.warning(f"Session terminée avec erreur, reconnexion dans {self.RECONNECT_DELAY} secondes")
                    if self.print_log:
                        print(f"Session terminée avec erreur, reconnexion dans {self.RECONNECT_DELAY} secondes")
                
                # Pause avant la reconnexion
                time.sleep(self.RECONNECT_DELAY)
                
            except Exception as e:
                logger.error(f"Erreur inattendue: {e}")
                if self.print_log:
                    print(f"Erreur inattendue: {e}")
                time.sleep(self.RECONNECT_DELAY)

    def connect_and_monitor(self):
        """Établit la connexion au PABX et commence la surveillance"""
        client_sock = None
        try:
            # Créer et connecter le socket
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(10)  # Timeout initial pour la connexion
            
            logger.info(f"Connexion au PABX {self.PABX_IP}:{self.PABX_PORT}...")
            client_sock.connect((self.PABX_IP, self.PABX_PORT))
            logger.info("Connexion établie avec succès")
            
            # Séquence d'initialisation
            # 1. Identification
            ident_cmd = b"\x42"
            logger.info(f"Envoi commande d'identification: {self.bytes_to_hex(ident_cmd)}")
            client_sock.sendall(ident_cmd)
            response = client_sock.recv(1024)
            logger.info(f"Réponse d'identification: {self.bytes_to_hex(response)}")
            time.sleep(2)
            
            # 2. Établissement de la session
            session_cmd = self.hex_to_bytes(
                "00 46 60 44 80 02 07 80 A1 07 06 05 2B 0C 00 81 34 BE 35 "
                "28 33 06 07 2B 0C 00 81 5A 81 48 A0 28 30 26 03 02 03 C0 "
                "30 16 80 04 03 E7 B6 48 81 06 02 5F FD 03 FE A0 83 02 06 "
                "C0 84 02 03 F0 30 08 82 02 03 D8 83 02 06 C0"
            )
            logger.info(f"Envoi commande de session")
            client_sock.sendall(session_cmd)
            response = client_sock.recv(1024)
            logger.info(f"Réponse commande de session reçue: {len(self.bytes_to_hex(response))} octets")
            time.sleep(2)
            
            # 3. Démarrer la surveillance pour chaque appareil
            for device in self.DEVICES_TO_MONITOR:
                # StartMonitor
                mon_cmd = self.build_start_monitor_cmd(device)
                logger.info(f"Envoi StartMonitor pour {device}")
                client_sock.sendall(mon_cmd)
                try:
                    response = client_sock.recv(1024)
                    hex_response = self.bytes_to_hex(response)
                    logger.info(f"Réponse StartMonitor pour {device}: {hex_response}")
                    
                    # Même décodage que pour le snapshot puisqu'ils ont un format similaire
                    monitor_info = self.decode_snapshot_response(hex_response, device)
                    monitor_info["type"] = "START_MONITOR_RESPONSE"
                    
                    # Envoyer à MQTT
                    self.send_mqtt_message(monitor_info)
                except socket.timeout:
                    logger.warning(f"Pas de réponse pour StartMonitor {device}")
                time.sleep(2)
                
                # Snapshot
                snap_cmd = self.build_snapshot_cmd(device)
                logger.info(f"Envoi Snapshot pour {device}")
                client_sock.sendall(snap_cmd)
                try:
                    response = client_sock.recv(1024)
                    hex_response = self.bytes_to_hex(response)
                    logger.info(f"Réponse Snapshot pour {device}: {hex_response}")
                    
                    # Decoder la réponse Snapshot
                    snapshot_info = self.decode_snapshot_response(hex_response, device)
                    
                    # Envoyer à MQTT
                    #self.send_mqtt_message(snapshot_info)
                except socket.timeout:
                    logger.warning(f"Pas de réponse pour Snapshot {device}")
                time.sleep(2)
            
            # Passer en mode non-bloquant pour la boucle d'événements
            client_sock.setblocking(False)
            
            # Variable pour le suivi du temps
            last_keepalive = time.time()
            
            logger.info("Début de la surveillance des événements...")
            
            # Boucle principale de surveillance
            while True:
                current_time = time.time()
                
                # Envoyer un keepalive si nécessaire
                if current_time - last_keepalive >= self.KEEPALIVE_INTERVAL:
                    keepalive = self.build_keepalive_cmd()
                    keepalive_hex = self.bytes_to_hex(keepalive)
                    logger.info(f"Envoi keepalive: {keepalive_hex}")
                    try:
                        client_sock.sendall(keepalive)
                        last_keepalive = current_time
                        
                        # Envoyer à MQTT
                        self.send_mqtt_message({
                            "type": "KEEPALIVE_SENT",
                            "data": keepalive_hex,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })
                    except socket.error as e:
                        logger.error(f"Erreur envoi keepalive: {e}")
                        break
                
                # Vérifier s'il y a des données à recevoir
                try:
                    data = client_sock.recv(4096)
                    if data:
                        # Afficher les données reçues
                        hex_data = self.bytes_to_hex(data)
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        if self.print_log:
                            print(f"{timestamp} - RX: {hex_data}")
                        logger.info(f"Données reçues: {hex_data}")
                        
                        # Pour le moment, traitons chaque message comme un seul message
                        # Déterminer le type de message
                        message_type = self.identify_message_type(hex_data)
                        
                        # Traiter selon le type de message
                        if message_type == "KEEPALIVE_REQUEST":
                            # Répondre au keepalive
                            response = self.prepare_keepalive_response(data)
                            if response:
                                response_hex = self.bytes_to_hex(response)
                                logger.info(f"Envoi réponse keepalive: {response_hex}")
                                client_sock.sendall(response)
                                
                                # Note: Pas d'envoi MQTT pour les keepalive_response
                        elif message_type == "CALL_EVENT":
                            # Décoder l'événement d'appel
                            event_info = self.decode_csta_event(hex_data)

                            # Mettre à jour l'historique des appels
                            self.update_call_history(event_info)
                            
                            # Convertir la structure en format JSON pour MQTT
                            mqtt_payload = {
                                "type": event_info.get("type", "UNKNOWN_EVENT"),
                                "timestamp": timestamp,
                                "csta_timestamp": event_info.get("csta_timestamp", ""),
                                "call_id": event_info.get("call_id", ""),
                                "cross_ref_id": event_info.get("cross_ref_id", ""),
                                "devices": {}
                            }
                            
                            # Ajouter les différents périphériques avec leur rôle
                            device_keys = [
                                ("device", "primary"), 
                                ("calling_device", "calling"),
                                ("called_device", "called"),
                                ("holding_device", "holding"),
                                ("retrieving_device", "retrieving"),
                                ("transferring_device", "transferring"),
                                ("transferred_to_device", "transferred_to"),
                                ("diverted_to_device", "diverted_to")
                            ]
                            
                            for key, role in device_keys:
                                if key in event_info and event_info[key]:
                                    mqtt_payload["devices"][role] = event_info[key]
                            
                            # Ajouter d'autres informations importantes
                            if "cause" in event_info:
                                mqtt_payload["cause"] = event_info["cause"]
                            if "cause_code" in event_info:
                                mqtt_payload["cause_code"] = event_info["cause_code"]
                            if "connection_state_desc" in event_info:
                                mqtt_payload["connection_state"] = event_info["connection_state_desc"]
                            if "description" in event_info:
                                mqtt_payload["description"] = event_info["description"]
                            
                            # Envoyer à MQTT
                            self.send_mqtt_message(mqtt_payload)
                            
                            # Log détaillé de l'événement
                            if "description" in event_info:
                                logger.info(f"Événement: {event_info['type']} - {event_info['description']}")
                            else:
                                logger.info(f"Événement: {event_info['type']}")
                                
                            # Afficher les détails pour debugging
                            if self.print_log:
                                print(f"  {event_info.get('type', 'UNKNOWN')}")
                            if self.print_log:
                                print(f"    Call ID: {event_info.get('call_id', 'N/A')}")
                            if self.print_log:
                                print(f"    CrossRef: {event_info.get('cross_ref_id', 'N/A')}")
                            for key, val in event_info.items():
                                if key.endswith('device') and val:
                                    if self.print_log:
                                        print(f"    {key}: {val}")
                        else:
                            # Pour les autres types, envoyer les données brutes
                            self.send_mqtt_message({
                                "type": message_type,
                                "timestamp": timestamp
                            })
                    else:
                        # Connexion fermée par le serveur
                        logger.warning("Connexion fermée par le serveur")
                        break
                    
                except (socket.error, BlockingIOError):
                    # Aucune donnée disponible, attendre un peu
                    time.sleep(0.1)
                
                except Exception as e:
                    logger.error(f"Erreur dans la boucle de surveillance: {e}")
                    break
            
            # Fin de la session
            logger.info("Fin de la session de surveillance")
            return True
            
        except socket.error as e:
            logger.error(f"Erreur de socket: {e}")
            return False
        
        finally:
            # Fermer le socket dans tous les cas
            if client_sock:
                try:
                    client_sock.close()
                    logger.info("Socket fermé")
                except:
                    pass

    def signal_handler(self, sig, frame):
        """Gestionnaire de signaux pour l'arrêt propre"""
        logger.info(f"Signal {sig} reçu, arrêt en cours...")
        if self.print_log:
            print(f"Signal {sig} reçu, arrêt en cours...")
        
        # Créer un socket pour la démonitoration
        try:
            demontior_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            demontior_sock.settimeout(5)  # Timeout court pour la déconnexion
            demontior_sock.connect((self.PABX_IP, self.PABX_PORT))
            
            # Identification
            ident_cmd = b"\x42"
            demontior_sock.sendall(ident_cmd)
            response = demontior_sock.recv(1024)
            
            # Établissement de la session pour démonitorer
            session_cmd = self.hex_to_bytes(
                "00 46 60 44 80 02 07 80 A1 07 06 05 2B 0C 00 81 34 BE 35 "
                "28 33 06 07 2B 0C 00 81 5A 81 48 A0 28 30 26 03 02 03 C0 "
                "30 16 80 04 03 E7 B6 48 81 06 02 5F FD 03 FE A0 83 02 06 "
                "C0 84 02 03 F0 30 08 82 02 03 D8 83 02 06 C0"
            )
            demontior_sock.sendall(session_cmd)
            response = demontior_sock.recv(1024)
            
            # Démonitorer chaque appareil
            for device in self.DEVICES_TO_MONITOR:
                logger.info(f"Démonitoration de {device}")
                stop_cmd = self.build_stop_monitor_cmd(device)
                demontior_sock.sendall(stop_cmd)
                try:
                    response = demontior_sock.recv(1024)
                    logger.info(f"Réponse StopMonitor pour {device}: {self.bytes_to_hex(response)}")
                except socket.timeout:
                    logger.warning(f"Pas de réponse pour StopMonitor {device}")
                time.sleep(0.5)
            
            # Fermer le socket de démonitoration
            demontior_sock.close()
            logger.info("Tous les postes ont été démonitorés avec succès")
            if self.print_log:
                print("Tous les postes ont été démonitorés avec succès")
        except Exception as e:
            logger.error(f"Erreur lors de la démonitoration: {e}")
            if self.print_log:
                print(f"Erreur lors de la démonitoration: {e}")
        
        # Fermer la connexion MQTT
        if self.mqtt_client:
            try:
                self.mqtt_client.loop_stop()
                self.mqtt_client.disconnect()
                logger.info("Connexion MQTT fermée")
                if self.print_log:
                    print("Connexion MQTT fermée")
            except:
                pass
        
        logger.info("Programme arrêté")
        if self.print_log:
            print("Programme arrêté")
        sys.exit(0)

    def log_call_history(self, call):
        """Affiche l'historique complet d'un appel dans les logs avec formatage amélioré."""
        events_summary = []
        for ev in call["events"]:
            events_summary.append(f"{ev['timestamp']} - {ev['type']}")

        summary = (
            f"\n{'=' * 60}\n"
            f"HISTORIQUE D'APPEL - ID: {call['call_id']}\n"
            f"{'=' * 60}\n"
            f"De: {call.get('calling_number', 'inconnu')}"
        )
        
        if call.get('caller_name'):
            summary += f" ({call['caller_name']})"
        
        summary += (
            f"\nVers: {call.get('called_number', 'inconnu')}\n"
        )
        
        if call.get('called_extension'):
            summary += f"Extension interne: {call.get('called_extension')}\n"
        
        # Afficher la direction si disponible
        if call.get('direction'):
            summary += f"Direction: {call.get('direction').upper()}\n"
            
        summary += (
            f"Début: {call.get('start_time', 'inconnu')}\n"
            f"Fin: {call.get('end_time', 'inconnu')}\n"
            f"Durée: {call.get('duration', 0)} secondes\n"
            f"Statut final: {call.get('status', 'inconnu')}\n"
        )
        
        # Ajouter des informations sur les transferts si disponibles
        if any("transfer" in key for key in call.keys()):
            summary += f"\n{'=' * 30} TRANSFERT {'=' * 30}\n"
            for key, value in call.items():
                if "transfer" in key:
                    summary += f"{key}: {value}\n"
        
        # Ajouter des informations sur les mises en attente si disponibles
        if "hold_time" in call:
            summary += f"\n{'=' * 30} ATTENTE {'=' * 30}\n"
            summary += f"Mise en attente: {call.get('hold_time')}\n"
            if "retrieve_time" in call:
                summary += f"Récupération: {call.get('retrieve_time')}\n"
            if "last_hold_duration" in call:
                summary += f"Durée d'attente: {call.get('last_hold_duration')} secondes\n"
        
        # Journal des événements
        summary += (
            f"\n{'=' * 30} ÉVÉNEMENTS ({len(events_summary)}) {'=' * 30}\n"
            f"{chr(10).join(events_summary)}\n"
            f"{'=' * 60}\n"
        )
        
        logger.info(summary)


      
def main():
    """Fonction principale"""
    # Utiliser args.printLog pour définir le comportement d'affichage
    monitor = CSTAMonitor(print_log=args.printLog, config_file=args.config)
    
    # Afficher les options de démarrage
    log_status = []
    if args.printLog:
        log_status.append("logs console activés")
    if args.trace:
        log_status.append("logs fichier activés")
    
    status_message = "CSTA Monitor démarré"
    if log_status:
        status_message += f" ({', '.join(log_status)})"
    
    logger.info(status_message)
    if args.printLog:
        print(status_message)
    
    monitor.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Programme arrêté par l'utilisateur")
        if args.printLog:  # Ajoutez cette condition
            print("Programme arrêté par l'utilisateur")
    except Exception as e:
        logger.critical(f"Erreur fatale: {e}")
        if args.printLog:  # Ajoutez cette condition
            print(f"Erreur fatale: {e}")
        sys.exit(1)