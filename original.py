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
from datetime import datetime
import paho.mqtt.client as mqtt

# Ajout du parser d'arguments pour --printLog
parser = argparse.ArgumentParser(description='CSTA Monitor pour OXE PBX')
parser.add_argument('--printLog', action='store_true', help='Activer l\'affichage des logs dans la console')
args = parser.parse_args()

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("csta_monitor.log"),
        logging.StreamHandler(sys.stdout) if args.printLog else logging.NullHandler()
    ]
)
logger = logging.getLogger(__name__)

class CSTAMonitor:
    def __init__(self, print_log=False):
        # Flag pour activer/désactiver les print
        self.print_log = print_log
        
        # Configuration CSTA
        self.PABX_IP = "10.134.100.113"
        self.PABX_PORT = 2555
        self.DEVICES_TO_MONITOR = [
            "24001","24002", "24003", "24004", "24005", "24006",
            "24007", "24120", "24151", "24152", "24153", "24738"
        ]
        self.RECONNECT_DELAY = 30      # secondes
        self.KEEPALIVE_INTERVAL = 30   # secondes
        
        # Configuration MQTT
        self.MQTT_BROKER = "10.208.4.11"
        self.MQTT_PORT = 1883
        self.MQTT_TOPIC = "pabx/csta/monitoring"
        self.MQTT_USER = "smallfoot"
        self.MQTT_PASSWORD = "mdpsfi"
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
            client.connect(self.MQTT_BROKER, self.MQTT_PORT, 60)
            client.loop_start()
            return client
        except Exception as e:
            logger.error(f"Erreur initialisation MQTT: {e}")
            return None
    
    def on_mqtt_connect(self, client, userdata, flags, rc):
        """Callback à la connexion MQTT"""
        if rc == 0:
            logger.info(f"MQTT connecté à {self.MQTT_BROKER}:{self.MQTT_PORT}")
        else:
            logger.error(f"Échec connexion MQTT, code: {rc}")
    
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
                    6: "fail"
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
                    0x16: "newCall",
                    0x30: "normalClearing",
                    0x0B: "callPickup",
                    0x0D: "destNotObtainable",
                    0x25: "consultation",
                    0x2E: "networkSignal",
                    0x03: "newConnection"
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