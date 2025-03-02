#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# v2.3.0

import socket
import sys
import time
import logging
import binascii
import json
from datetime import datetime

import paho.mqtt.client as mqtt

# --------------------------------------------------------------------
# Configuration du logging
# --------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("csta_monitor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------
# Configuration CSTA
# --------------------------------------------------------------------
PABX_IP = "10.134.100.113"  # Adresse IP du PABX OXE
PABX_IPCHU = "10.134.3.13"  # Adresse IP du PABX OXE
PABX_PORT = 2555         # Port standard CSTA Telnet pour OXE

# Liste des postes à surveiller (5 chiffres chacun)
DEVICES_TO_MONITORCHU = [
    "29535",
    "29707",
    "29538",
    "29537",
    "75219",
    "14000",
    "29500"
]
DEVICES_TO_MONITOR = [
    "24101",
    "24102",
    "24103",
    "24104",
    "24105",
    "24119",
    "24120",
    "24151",
    "24152",
    "24153"
]

RECONNECT_DELAY = 30     # Délai avant reconnexion en cas d'échec
SESSION_TIME = 300       # Durée maximale d'une session (5 minutes)
KEEPALIVE_INTERVAL = 15  # Intervalle d'envoi des keepalives en secondes

# --------------------------------------------------------------------
# Configuration MQTT
# --------------------------------------------------------------------
MQTT_BROKER = "10.208.4.11"
MQTT_PORT = 1883
MQTT_TOPIC = "pabx/csta/monitoring"
MQTT_USER = "smallfoot"
MQTT_PASSWORD = "mdpsfi"

mqtt_client = None

# --------------------------------------------------------------------
# Structure pour suivre les appels en cours
# --------------------------------------------------------------------
active_calls = {}

# Ajouter cette définition de variable globale juste après les autres variables globales
# (comme active_calls)

# Dictionnaire pour stocker les exemples complets de chaque type d'événement
event_full_examples = {}

# Ajouter ces fonctions juste avant la définition de connect_and_monitor

def extract_ascii_from_hex(hex_data, start_idx, max_length=20):
    """
    Extrait une chaîne ASCII à partir de données hexadécimales
    
    Args:
        hex_data (str): Données hexadécimales
        start_idx (int): Position de départ
        max_length (int): Longueur maximale à extraire
        
    Returns:
        str: Chaîne ASCII extraite
    """
    result = ""
    for i in range(0, max_length*3, 3):
        if start_idx + i >= len(hex_data):
            break
        byte_hex = hex_data[start_idx + i:start_idx + i + 2]
        try:
            byte_val = int(byte_hex, 16)
            if 32 <= byte_val <= 126:  # Caractères ASCII imprimables
                result += chr(byte_val)
            else:
                if result:  # On s'arrête au premier caractère non-imprimable après une séquence
                    break
        except:
            break
    return result

def analyze_event_structure(hex_data):
    """
    Analyse la structure d'un message CSTA en hexadécimal
    et retourne une description de ses principales sections
    
    Args:
        hex_data (str): Données hexadécimales du message
        
    Returns:
        dict: Structure du message avec ses sections principales
    """
    structure = {
        "total_length": "",
        "invoke_id": "",
        "event_code": "",
        "sections": []
    }
    
    # Extraire la longueur totale (premiers octets)
    if len(hex_data) >= 5:
        structure["total_length"] = hex_data[0:5]
    
    # Rechercher l'identifiant d'invocation
    invoke_idx = hex_data.find("02 02")
    if invoke_idx != -1:
        structure["invoke_id"] = hex_data[invoke_idx:invoke_idx+14]
    
    # Rechercher le code d'événement
    event_code_idx = hex_data.find("02 01")
    if event_code_idx != -1:
        structure["event_code"] = hex_data[event_code_idx:event_code_idx+8]
    
    # Analyser les sections spécifiques selon le type d'événement
    if "02 01 15" in hex_data:  # NEW_CALL, SERVICE_INITIATED ou FAILED
        if "4E 01 06" in hex_data:  # EVT_FAILED
            structure["sections"].append({
                "name": "State",
                "value": "4E 01 06 (failure)",
                "position": hex_data.find("4E 01 06")
            })
        
        # Rechercher les appareils
        calling_idx = hex_data.find("63 07 84 05")
        if calling_idx != -1:
            extracted = extract_ascii_from_hex(hex_data, calling_idx + 12)
            structure["sections"].append({
                "name": "Calling Device",
                "value": extracted,
                "position": calling_idx
            })
        
        called_idx = hex_data.find("62 07 84 05")
        if called_idx != -1:
            extracted = extract_ascii_from_hex(hex_data, called_idx + 12)
            structure["sections"].append({
                "name": "Called Device",
                "value": extracted,
                "position": called_idx
            })
        
        # Rechercher l'horodatage
        time_idx = hex_data.find("17 0D")
        if time_idx != -1:
            structure["sections"].append({
                "name": "Timestamp",
                "value": hex_data[time_idx:time_idx+50],
                "position": time_idx
            })
    
    # Ajouter d'autres analyses spécifiques pour d'autres types d'événements
    elif "02 01 01" in hex_data:  # CALL_CLEARED
        cause_idx = hex_data.find("0A 01")
        if cause_idx != -1:
            cause_code = hex_data[cause_idx+6:cause_idx+8]
            structure["sections"].append({
                "name": "Clearing Cause",
                "value": f"0A 01 {cause_code}",
                "position": cause_idx
            })
    
    # ... autres types d'événements ...
    
    return structure

def log_full_hex_message(event_type, hex_data):
    """
    Enregistre un message hexadécimal complet pour un type d'événement
    Si c'est le premier exemple rencontré pour ce type, l'enregistre dans le dictionnaire
    """
    if event_type not in event_full_examples:
        event_full_examples[event_type] = hex_data
        logger.info(f"=== NOUVEL EXEMPLE COMPLET POUR {event_type} ===")
        logger.info(f"{hex_data}")
        logger.info("=" * 50)

def print_all_event_examples():
    """
    Affiche tous les exemples complets enregistrés
    """
    logger.info("=== EXEMPLES COMPLETS PAR TYPE D'ÉVÉNEMENT CSTA ===")
    for event_type, hex_data in event_full_examples.items():
        logger.info(f"\n\n=== TYPE: {event_type} ===")
        logger.info(f"{hex_data}")
        logger.info("=" * 50)
    logger.info("=== FIN DES EXEMPLES COMPLETS ===")

def log_analyzed_event(event_type, hex_data):
    """
    Enregistre un message avec sa structure analysée
    
    Args:
        event_type (str): Type d'événement
        hex_data (str): Données hexadécimales du message
    """
    structure = analyze_event_structure(hex_data)
    
    # Formatter l'analyse pour le log
    analysis = f"\n=== ANALYSE DE L'ÉVÉNEMENT {event_type} ===\n"
    analysis += f"Longueur totale: {structure['total_length']}\n"
    analysis += f"Identifiant d'invocation: {structure['invoke_id']}\n"
    analysis += f"Code d'événement: {structure['event_code']}\n"
    analysis += "\nSections détectées:\n"
    
    for section in structure["sections"]:
        analysis += f"- {section['name']}: {section['value']} (position {section['position']})\n"
    
    analysis += "\nDonnées hexadécimales complètes:\n"
    analysis += hex_data
    analysis += f"\n{'=' * 50}\n"
    
    # Enregistrer dans le log
    logger.info(analysis)
    
    # Enregistrer aussi l'exemple complet
    if event_type not in event_full_examples:
        event_full_examples[event_type] = hex_data
# --------------------------------------------------------------------
# Fonctions utilitaires de suivi des appels
# --------------------------------------------------------------------
def track_call(event):
    """
    Suit le cheminement d'un appel à travers différents événements CSTA.
    Mise à jour pour gérer tous les types d'événements standard et assurer l'envoi des historiques.
    """
    if not event or "type" not in event or "call_id" not in event:
        return

    call_id = event["call_id"]
    event_type = event["type"]
    timestamp = event.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Si l'appel n'est pas encore connu
    if call_id not in active_calls:
        active_calls[call_id] = {
            "call_id": call_id,
            "start_time": timestamp,
            "events": [],
            "status": "new"
        }

    # Ajout de cet événement dans l'historique
    active_calls[call_id]["events"].append({
        "type": event_type,
        "timestamp": timestamp,
        "details": event
    })

    # Mise à jour du statut de l'appel selon le type d'événement
    if event_type == "NEW_CALL":
        active_calls[call_id]["status"] = "new"
        active_calls[call_id]["calling_number"] = event.get("calling_number")
        active_calls[call_id]["called_number"] = event.get("called_number")
        active_calls[call_id]["called_extension"] = event.get("called_extension")
        
        # Détermination de la direction de l'appel
        if event.get("called_extension") == event.get("calling_number"):
            active_calls[call_id]["direction"] = "outgoing"
        else:
            active_calls[call_id]["direction"] = "incoming"
        
        # Si l'état de connexion est disponible
        if "connection_state_desc" in event:
            active_calls[call_id]["connection_state"] = event.get("connection_state_desc")
    
    elif event_type == "EVT_SERVICE_INITIATED":
        active_calls[call_id]["status"] = "initiated"
        active_calls[call_id]["initiated_device"] = event.get("initiated_device")
        # Si nous avons également des infos sur l'appelant/appelé à cette étape
        if "connection_call" in event:
            active_calls[call_id]["call_id"] = event["connection_call"]
        if "cause_code" in event and event["cause_code"] == 22:  # newCall
            active_calls[call_id]["direction"] = "outgoing"
    
    elif event_type == "EVT_FAILED":
        active_calls[call_id]["status"] = "failed"
        active_calls[call_id]["failing_device"] = event.get("failing_device")
        active_calls[call_id]["called_device"] = event.get("called_device")
        active_calls[call_id]["failure_reason"] = event.get("cause", "unknown")
        active_calls[call_id]["failure_code"] = event.get("cause_code")
        active_calls[call_id]["end_time"] = timestamp
        
        # On log l'historique en clair pour les appels échoués
        log_call_history(active_calls[call_id])
        
        # On envoie l'historique complet sur MQTT pour les appels échoués
        send_call_history_mqtt(active_calls[call_id])
    
    elif event_type == "DELIVERED":
        active_calls[call_id]["status"] = "ringing"
        # Mettre à jour les informations d'appel si disponibles
        if "calling_number" in event:
            active_calls[call_id]["calling_number"] = event.get("calling_number")
        if "called_number" in event:
            active_calls[call_id]["called_number"] = event.get("called_number")
        if "called_extension" in event:
            active_calls[call_id]["called_extension"] = event.get("called_extension")
        
        # Déterminer la direction si pas encore fait
        if "direction" not in active_calls[call_id]:
            active_calls[call_id]["direction"] = "incoming"  # Par défaut, considéré comme entrant
    
    elif event_type == "ESTABLISHED":
        active_calls[call_id]["status"] = "connected"
        active_calls[call_id]["answer_time"] = timestamp
        
        # Mettre à jour l'état de connexion
        if "connection_state_desc" in event:
            active_calls[call_id]["connection_state"] = event.get("connection_state_desc")
    
    elif event_type == "HELD":
        active_calls[call_id]["status"] = "held"
        active_calls[call_id]["hold_time"] = timestamp
        active_calls[call_id]["holding_device"] = event.get("holding_device")
    
    elif event_type == "RETRIEVED":
        active_calls[call_id]["status"] = "connected"  # Revenir à l'état connecté
        active_calls[call_id]["retrieve_time"] = timestamp
        active_calls[call_id]["retrieving_device"] = event.get("retrieving_device")
        
        # Calculer le temps passé en attente
        if "hold_time" in active_calls[call_id]:
            hold_duration = calculate_duration(
                active_calls[call_id]["hold_time"], 
                timestamp
            )
            active_calls[call_id]["last_hold_duration"] = hold_duration
    
    elif event_type == "DIVERTED":
        active_calls[call_id]["status"] = "diverted"
        active_calls[call_id]["divert_time"] = timestamp
        active_calls[call_id]["diverted_to"] = event.get("diverted_to_device")
        active_calls[call_id]["diversion_type"] = event.get("diversion_type_desc")
    
    elif event_type == "CONFERENCED":
        active_calls[call_id]["status"] = "conferenced"
        active_calls[call_id]["conference_time"] = timestamp
        active_calls[call_id]["conference_id"] = event.get("conference_id")
    
    elif event_type == "TRANSFERRED":
        active_calls[call_id]["status"] = "transferred"
        active_calls[call_id]["transfer_time"] = timestamp
        active_calls[call_id]["transferring_device"] = event.get("transferring_device")
        active_calls[call_id]["transferred_to"] = event.get("transferred_to_device")
    
    # Correction: Condition pour les événements de fin d'appel (formats anciens et nouveaux)
    elif event_type == "CALL_CLEARED" or event_type == "EVT_CONNECTION_CLEARED":
        active_calls[call_id]["status"] = "completed"
        active_calls[call_id]["end_time"] = timestamp
        active_calls[call_id]["duration"] = calculate_duration(
            active_calls[call_id].get("start_time"), 
            timestamp
        )

        logger.info(f"Fin d'appel détectée pour ID {call_id} - Génération de l'historique...")

        # On log l'historique en clair
        log_call_history(active_calls[call_id])
   
        # On envoie l'historique complet sur MQTT
        send_call_history_mqtt(active_calls[call_id])
def track_call2(event):
    """
    Suit le cheminement d'un appel à travers différents événements CSTA.
    Mise à jour pour gérer tous les types d'événements standard.
    """
    if not event or "type" not in event or "call_id" not in event:
        return

    call_id = event["call_id"]
    event_type = event["type"]
    timestamp = event.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Si l'appel n'est pas encore connu
    if call_id not in active_calls:
        active_calls[call_id] = {
            "call_id": call_id,
            "start_time": timestamp,
            "events": [],
            "status": "new"
        }

    # Ajout de cet événement dans l'historique
    active_calls[call_id]["events"].append({
        "type": event_type,
        "timestamp": timestamp,
        "details": event
    })

    # Mise à jour du statut de l'appel selon le type d'événement
    if event_type == "NEW_CALL":
        active_calls[call_id]["status"] = "new"
        active_calls[call_id]["calling_number"] = event.get("calling_number")
        active_calls[call_id]["called_number"] = event.get("called_number")
        active_calls[call_id]["called_extension"] = event.get("called_extension")
        
        # Détermination de la direction de l'appel
        if event.get("called_extension") == event.get("calling_number"):
            active_calls[call_id]["direction"] = "outgoing"
        else:
            active_calls[call_id]["direction"] = "incoming"
        
        # Si l'état de connexion est disponible
        if "connection_state_desc" in event:
            active_calls[call_id]["connection_state"] = event.get("connection_state_desc")
    
    elif event_type == "EVT_SERVICE_INITIATED":
        active_calls[call_id]["status"] = "initiated"
        active_calls[call_id]["initiated_device"] = event.get("initiated_device")
        # Si nous avons également des infos sur l'appelant/appelé à cette étape
        if "connection_call" in event:
            active_calls[call_id]["call_id"] = event["connection_call"]
        if "cause_code" in event and event["cause_code"] == 22:  # newCall
            active_calls[call_id]["direction"] = "outgoing"
    
    elif event_type == "EVT_FAILED":
        active_calls[call_id]["status"] = "failed"
        active_calls[call_id]["failing_device"] = event.get("failing_device")
        active_calls[call_id]["called_device"] = event.get("called_device")
        active_calls[call_id]["failure_reason"] = event.get("cause", "unknown")
        active_calls[call_id]["failure_code"] = event.get("cause_code")
        active_calls[call_id]["end_time"] = timestamp
        
        # On log l'historique en clair pour les appels échoués
        log_call_history(active_calls[call_id])
        
        # On envoie l'historique complet sur MQTT pour les appels échoués
        send_call_history_mqtt(active_calls[call_id])
    
    elif event_type == "DELIVERED":
        active_calls[call_id]["status"] = "ringing"
        # Mettre à jour les informations d'appel si disponibles
        if "calling_number" in event:
            active_calls[call_id]["calling_number"] = event.get("calling_number")
        if "called_number" in event:
            active_calls[call_id]["called_number"] = event.get("called_number")
        if "called_extension" in event:
            active_calls[call_id]["called_extension"] = event.get("called_extension")
        
        # Déterminer la direction si pas encore fait
        if "direction" not in active_calls[call_id]:
            active_calls[call_id]["direction"] = "incoming"  # Par défaut, considéré comme entrant
    
    elif event_type == "ESTABLISHED":
        active_calls[call_id]["status"] = "connected"
        active_calls[call_id]["answer_time"] = timestamp
        
        # Mettre à jour l'état de connexion
        if "connection_state_desc" in event:
            active_calls[call_id]["connection_state"] = event.get("connection_state_desc")
    
    elif event_type == "HELD":
        active_calls[call_id]["status"] = "held"
        active_calls[call_id]["hold_time"] = timestamp
        active_calls[call_id]["holding_device"] = event.get("holding_device")
    
    elif event_type == "RETRIEVED":
        active_calls[call_id]["status"] = "connected"  # Revenir à l'état connecté
        active_calls[call_id]["retrieve_time"] = timestamp
        active_calls[call_id]["retrieving_device"] = event.get("retrieving_device")
        
        # Calculer le temps passé en attente
        if "hold_time" in active_calls[call_id]:
            hold_duration = calculate_duration(
                active_calls[call_id]["hold_time"], 
                timestamp
            )
            active_calls[call_id]["last_hold_duration"] = hold_duration
    
    elif event_type == "DIVERTED":
        active_calls[call_id]["status"] = "diverted"
        active_calls[call_id]["divert_time"] = timestamp
        active_calls[call_id]["diverted_to"] = event.get("diverted_to_device")
        active_calls[call_id]["diversion_type"] = event.get("diversion_type_desc")
    
    elif event_type == "CONFERENCED":
        active_calls[call_id]["status"] = "conferenced"
        active_calls[call_id]["conference_time"] = timestamp
        active_calls[call_id]["conference_id"] = event.get("conference_id")
    
    elif event_type == "TRANSFERRED":
        active_calls[call_id]["status"] = "transferred"
        active_calls[call_id]["transfer_time"] = timestamp
        active_calls[call_id]["transferring_device"] = event.get("transferring_device")
        active_calls[call_id]["transferred_to"] = event.get("transferred_to_device")
    
    elif event_type == "CALL_CLEARED" or event_type == "CALL_CLEARED":
        active_calls[call_id]["status"] = "completed"
        active_calls[call_id]["end_time"] = timestamp
        active_calls[call_id]["duration"] = calculate_duration(
            active_calls[call_id].get("start_time"), 
            timestamp
        )

        # On log l'historique en clair
        log_call_history(active_calls[call_id])
   
        # On envoie l'historique complet sur MQTT
        send_call_history_mqtt(active_calls[call_id])
def calculate_duration(start_time, end_time):
    """Calcule la durée d'un appel en secondes."""
    try:
        start = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        return (end - start).total_seconds()
    except:
        return 0

def log_call_history(call):
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

def send_call_history_mqtt(call):
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
            "type": ev.get("type", "")
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
    mqtt_topic = f"{MQTT_TOPIC}/history"
    payload = json.dumps(data, ensure_ascii=False)
    
    try:
        mqtt_client.publish(mqtt_topic, payload)
        logger.info(f"Historique d'appel ID {call['call_id']} publié sur MQTT: {mqtt_topic}")
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de l'historique sur MQTT: {e}")

def send_call_history_mqtt(call):
    """
    Envoie l'historique complet de l'appel en JSON sur MQTT.
    On crée un objet "CALL_HISTORY" avec tous les champs utiles.
    """
    data = {
        "type": "CALL_HISTORY",
        "call_id": call["call_id"],
        "calling_number": call.get("calling_number", "unknown"),
        "caller_name": call.get("caller_name", "unknown"),
        "called_number": call.get("called_number", "unknown"),
        "start_time": call.get("start_time", "unknown"),
        "end_time": call.get("end_time", "unknown"),
        "duration": call.get("duration", 0),
        "status": call.get("status", "unknown"),
        "events": []
    }
    for ev in call["events"]:
        data["events"].append({
            "timestamp": ev.get("timestamp", ""),
            "type": ev.get("type", "")
        })

    # Publier sur MQTT
    send_mqtt_event(data)

# --------------------------------------------------------------------
# Fonctions utilitaires pour le format hexadécimal et keepalives
# --------------------------------------------------------------------
def bytes_to_hex(data):
    if not data:
        return "AUCUNE DONNÉE"
    hex_str = binascii.hexlify(data).decode('utf-8')
    return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2)).upper()

def hex_to_bytes(hex_str):
    hex_str = hex_str.replace(" ", "")
    return binascii.unhexlify(hex_str)

def format_keepalive(invoke_id):
    id_hi = (invoke_id >> 8) & 0xFF
    id_lo = invoke_id & 0xFF
    cmd = f"00 0C A1 0A 02 02 {id_hi:02X} {id_lo:02X} 02 01 34 0A 01 02"
    return hex_to_bytes(cmd)

def format_keepalive_response(id_hi, id_lo):
    return hex_to_bytes(f"00 0D A2 0B 02 02 {id_hi:02X} {id_lo:02X} 30 05 02 01 34 05 00")

# --------------------------------------------------------------------
# Extraction ASCII
# --------------------------------------------------------------------
def extract_ascii_number(hex_data, start_idx, length=10):
    number = ""
    for i in range(0, length * 3, 3):  # Chaque caractère = 3 caractères en hex_data ("30 ")
        if start_idx + i >= len(hex_data):
            break
        byte_hex = hex_data[start_idx + i : start_idx + i + 2]
        if byte_hex in ["30","31","32","33","34","35","36","37","38","39"]:
            number += chr(int(byte_hex, 16))
        else:
            # On arrête la lecture si ce n'est plus un chiffre
            if len(number) > 0:
                break
            return number

def extract_ascii_string(hex_data, start_idx, length=20):
    try:
        result = ""
        for i in range(0, length*3, 3):
            if start_idx + i >= len(hex_data):
                break
            byte_hex = hex_data[start_idx + i:start_idx + i + 2]
            byte_val = int(byte_hex, 16)
            if 32 <= byte_val <= 126:
                result += chr(byte_val)
            else:
                if i > 0:
                    break
        return result
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction de la chaîne: {e}")
        return ""

# --------------------------------------------------------------------
# Commandes StartMonitor / Snapshot
# --------------------------------------------------------------------
def build_start_monitor_cmd(device):
    ascii_device = " ".join(f"{ord(c):02X}" for c in device)
    start_monitor_str = (
        "00 11 A1 0F "
        "02 01 01 "
        "02 01 47 "
        "30 07 "
        "80 05 "
        f"{ascii_device}"
    )
    return hex_to_bytes(start_monitor_str)

def build_snapshot_cmd(device):
    ascii_device = " ".join(f"{ord(c):02X}" for c in device)
    snapshot_str = (
        "00 0F A1 0D "
        "02 01 03 "
        "02 01 4A "
        "80 05 "
        f"{ascii_device}"
    )
    return hex_to_bytes(snapshot_str)

# --------------------------------------------------------------------
# MQTT
# --------------------------------------------------------------------
def init_mqtt_client():
    client = mqtt.Client()
    client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_start() 
    logger.info(f"MQTT connecté sur {MQTT_BROKER}:{MQTT_PORT}, topic={MQTT_TOPIC}")
    return client

def send_mqtt_event(event):
    if not event:
        return
    try:

                # Retirer le champ 'raw_hex' s'il est présent
        if "raw_hex" in event:
            del event["raw_hex"]
        # Éviter l’erreur en supprimant ou convertissant les bytes
        if "response" in event and isinstance(event["response"], bytes):
            del event["response"]

        # Ajout d'un timestamp si besoin
        if "parsed_at" not in event:
            event["parsed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

        # Si le type est KEEPALIVE, on ne publie pas
        if event.get("type") == "UNKNOWN" or event.get("type") == "KEEPALIVE":
            return

        payload = json.dumps(event, ensure_ascii=False)
        mqtt_client.publish(MQTT_TOPIC, payload)
        logger.info(f"MQTT Publish --> Topic: {MQTT_TOPIC} | Data: {payload}")

    except Exception as e:
        logger.error(f"Erreur lors de l'envoi MQTT: {e}")


def send_mqtt_eventBrute(event):
    """Envoie un événement CSTA (ou autre) en JSON sur MQTT."""
    if not event:
        return
    try:
        # Convertit tous les objets bytes en hex
        sanitize_for_json(event)

        # Ajout d'un timestamp local
        if "parsed_at" not in event:
            event["parsed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

        payload = json.dumps(event, ensure_ascii=False)
        mqtt_client.publish(MQTT_TOPIC, payload)
        logger.info(f"MQTT Publish --> Topic: {MQTT_TOPIC} | Data: {payload}")
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi MQTT: {e}")


# --------------------------------------------------------------------
# parse_event
# --------------------------------------------------------------------
def parse_event(data):
    """
    Fonction principale d'analyse des événements CSTA
    Identifie le type d'événement et extrait toutes les informations pertinentes
    """
    hex_data = bytes_to_hex(data)
    event_info = {
        "raw_hex": hex_data,
        "parsed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    }
    logger.debug(f"Full Hex Data: {hex_data}")
    
    # Détection du type d'événement
    event_type = detect_csta_event_type(hex_data)
    event_info["type"] = event_type
    
    # Extraction des informations communes à tous les événements
    common_info = extract_common_info(hex_data)
    event_info.update(common_info)
    
    # Extraction des informations sur les appareils (si pertinent)
    device_info = extract_device_info(hex_data)
    event_info.update(device_info)
    
    # Extraction des informations sur la connexion (si pertinent)
    connection_info = extract_connection_info(hex_data)
    event_info.update(connection_info)
    
    # Extraction des informations spécifiques selon le type d'événement
    if event_type == "HELD":
        held_info = extract_held_info(hex_data)
        event_info.update(held_info)
    
    elif event_type == "RETRIEVED":
        retrieved_info = extract_retrieved_info(hex_data)
        event_info.update(retrieved_info)
    
    elif event_type == "CONFERENCED":
        conferenced_info = extract_conferenced_info(hex_data)
        event_info.update(conferenced_info)
    
    elif event_type == "DIVERTED":
        diverted_info = extract_diverted_info(hex_data)
        event_info.update(diverted_info)
    
    elif event_type == "TRANSFERRED":
        transferred_info = extract_transferred_info(hex_data)
        event_info.update(transferred_info)
    
    elif event_type == "EVT_FAILED":
        # Maintient la compatibilité avec le code existant
        failed_info = extract_failed_info(hex_data)
        event_info.update(failed_info)
    
    elif event_type == "EVT_SERVICE_INITIATED":
        # Maintient la compatibilité avec le code existant
        service_info = extract_service_initiated_info(hex_data)
        event_info.update(service_info)
        
        # Extraction de l'appareil initiateur
        initiated_device = extract_initiated_device(hex_data)
        if initiated_device:
            event_info["initiated_device"] = initiated_device
    
    # Retour des informations extraites
    return event_info

# Fonctions d'extraction spécifiques pour SERVICE_INITIATED et FAILED
# qui sont référencées mais pourraient manquer dans votre code

def extract_service_initiated_info(hex_data):
    """Extrait les informations spécifiques au message EVT_SERVICE_INITIATED"""
    info = {}
    
    # Extraction du ConnectionCall (format 82 02 XX XX)
    try:
        call_id_idx = hex_data.find("82 02")
        if call_id_idx != -1:
            call_id_hex = hex_data[call_id_idx+6:call_id_idx+11].replace(" ", "")
            info["call_id"] = int(call_id_hex, 16)
    except Exception as e:
        logger.error(f"Erreur extraction call_id: {e}")
    
    # Extraction du CrossRefIdentifier
    try:
        xref_idx = hex_data.find("02 02")
        if xref_idx != -1:
            xref_hex = hex_data[xref_idx+6:xref_idx+11].replace(" ", "")
            info["cross_ref_identifier"] = int(xref_hex, 16)
    except Exception as e:
        logger.error(f"Erreur extraction cross_ref: {e}")
    
    # Extraction du LocalConnectionInfo
    try:
        conn_info_idx = hex_data.find("4E 01")
        if conn_info_idx != -1:
            conn_state = int(hex_data[conn_info_idx+6:conn_info_idx+8], 16)
            info["connection_state"] = conn_state
            info["connection_state_desc"] = {
                0: "null",
                1: "initiated",
                2: "alerting", 
                3: "connected",
                4: "hold",
                5: "queued",
                6: "fail"
            }.get(conn_state, f"unknown({conn_state})")
    except Exception as e:
        logger.error(f"Erreur extraction connection_state: {e}")
    
    # Extraction du DecodeCause
    try:
        cause_idx = hex_data.find("0A 01")
        if cause_idx != -1:
            cause_code = int(hex_data[cause_idx+6:cause_idx+8], 16)
            info["cause_code"] = cause_code
            info["cause"] = {
                22: "newCall", 
                48: "normalClearing",
                11: "callPickup"
            }.get(cause_code, f"unknown({cause_code})")
    except Exception as e:
        logger.error(f"Erreur extraction cause: {e}")
    
    return info

def extract_initiated_device(hex_data):
    """Extrait l'appareil initiateur d'un événement SERVICE_INITIATED"""
    try:
        # Recherche du pattern 55 04 01 suivi du numéro de poste
        init_dev_idx = hex_data.find("55 04 01")
        if init_dev_idx != -1:
            # Extraction du numéro de poste (5 chiffres = 10 caractères hex + espaces)
            init_dev_hex = hex_data[init_dev_idx+9:init_dev_idx+20].replace(" ", "")
            
            # Conversion Hex->ASCII
            device_bytes = bytes.fromhex(init_dev_hex)
            device = ""
            for b in device_bytes:
                if 48 <= b <= 57:  # ASCII des chiffres
                    device += chr(b)
                else:
                    break
            
            if device and len(device) > 0:
                return device
    except Exception as e:
        logger.error(f"Erreur extraction initiated_device: {e}")
    return None

def extract_failed_info(hex_data):
    """Extrait les informations spécifiques du message EVT_FAILED"""
    info = {}
    
    # Extraction du ConnectionCall (format 82 02 XX XX)
    try:
        call_id_idx = hex_data.find("82 02")
        if call_id_idx != -1:
            call_id_hex = hex_data[call_id_idx+6:call_id_idx+11].replace(" ", "")
            info["call_id"] = int(call_id_hex, 16)
    except Exception as e:
        logger.error(f"Erreur extraction call_id: {e}")
    
    # Extraction du CrossRefIdentifier
    try:
        xref_idx = hex_data.find("02 02")
        if xref_idx != -1:
            xref_hex = hex_data[xref_idx+6:xref_idx+11].replace(" ", "")
            info["cross_ref_identifier"] = int(xref_hex, 16)
    except Exception as e:
        logger.error(f"Erreur extraction cross_ref: {e}")
    
    # Extraction du FailingDevice (63 07 84 05 + numéro ASCII)
    try:
        failing_dev_idx = hex_data.find("63 07 84 05")
        if failing_dev_idx != -1:
            # Extraction de l'appareil en ASCII (ex: 32 39 35 33 38 = "29538")
            failing_device = ""
            for i in range(0, 15, 3):  # Maximum 5 chiffres
                pos = failing_dev_idx + 12 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        failing_device += chr(int(byte_hex, 16))
                    else:
                        break
            if failing_device:
                info["failing_device"] = failing_device
    except Exception as e:
        logger.error(f"Erreur extraction failing_device: {e}")
    
    # Extraction du CalledDevice (62 05 80 03 + identifiant ASCII) 
    try:
        called_dev_idx = hex_data.find("62 05 80 03")
        if called_dev_idx != -1:
            # L'identifiant peut contenir des chiffres ou des lettres
            called_device = ""
            for i in range(0, 15, 3):
                pos = called_dev_idx + 12 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    byte_val = int(byte_hex, 16)
                    if 32 <= byte_val <= 126:  # Caractères ASCII imprimables
                        called_device += chr(byte_val)
                    else:
                        break
            if called_device:
                info["called_device"] = called_device
    except Exception as e:
        logger.error(f"Erreur extraction called_device: {e}")
    
    # Extraction du LocalConnectionInfo (4E 01 XX)
    try:
        conn_info_idx = hex_data.find("4E 01")
        if conn_info_idx != -1:
            conn_state = int(hex_data[conn_info_idx+6:conn_info_idx+8], 16)
            info["connection_state"] = conn_state
            info["connection_state_desc"] = {
                0: "null",
                1: "initiated",
                2: "alerting", 
                3: "connected",
                4: "hold",
                5: "queued",
                6: "fail"
            }.get(conn_state, f"unknown({conn_state})")
    except Exception as e:
        logger.error(f"Erreur extraction connection_state: {e}")
    
    # Extraction du DecodeCause (0A 01 XX)
    try:
        cause_idx = hex_data.find("0A 01")
        if cause_idx != -1:
            cause_code = int(hex_data[cause_idx+6:cause_idx+8], 16)
            info["cause_code"] = cause_code
            info["cause"] = {
                22: "newCall", 
                48: "normalClearing",
                11: "callPickup",
                13: "destNotObtainable"
            }.get(cause_code, f"unknown({cause_code})")
    except Exception as e:
        logger.error(f"Erreur extraction cause: {e}")
    
    return info
# Add this import
import re

def detect_csta_event_type(hex_data):
    """
    Détecte le type d'événement CSTA ASN.1 basé sur son code d'identification
    Prend en compte le contexte pour éviter les faux positifs
    """
    # Détection prioritaire des keepalives
    if "A2 0A" in hex_data and ("02 01 34" in hex_data or "02 01 01 30 05 02 01 34" in hex_data or "02 01 03 30 05 02 01 34" in hex_data):
        return "KEEPALIVE"
    
    # Dictionnaire des codes d'événements et leurs descriptions
    event_codes = {
        "02 01 15": "NEW_CALL",            # Nouvel appel
        "02 01 01": "CALL_CLEARED",        # Appel terminé
        "02 01 03": "DELIVERED",           # Appel livré
        "02 01 04": "ESTABLISHED",         # Connexion établie
        "02 01 06": "HELD",                # Appel mis en attente
        "02 01 0B": "RETRIEVED",           # Appel récupéré
        "02 01 0C": "CONFERENCED",         # Appel mis en conférence
        "02 01 0E": "DIVERTED",            # Appel redirigé
        "02 01 0F": "TRANSFERRED"          # Appel transféré
    }
    
    # Recherche du code dans les données hexadécimales, en vérifiant le contexte
    for code, event_type in event_codes.items():
        if code in hex_data:
            # Vérifications supplémentaires pour éviter les faux positifs
            
            # Pour SERVICE_INITIATED et FAILED (qui partagent le même code 02 01 15)
            if code == "02 01 15":
                if "4E 01 06" in hex_data and "0A 01 0D" in hex_data:
                    return "EVT_FAILED"
                elif "55 04 01" in hex_data and "A5" in hex_data:
                    return "NEW_CALL"  # Format vraiment spécifique à newCall
                else:
                    return "EVT_SERVICE_INITIATED"
            
            # Pour CALL_CLEARED, vérifier que ce n'est pas un keepalive
            elif code == "02 01 01" and "A2 0A" in hex_data and "02 01 34" in hex_data:
                continue  # C'est un keepalive, pas un CALL_CLEARED
            
            # Pour DELIVERED, vérifier que ce n'est pas un keepalive
            elif code == "02 01 03" and "A2 0A" in hex_data and "02 01 34" in hex_data:
                continue  # C'est un keepalive, pas un DELIVERED
            
            # Pour les autres types d'événements, nous pouvons ajouter des 
            # vérifications supplémentaires si nécessaire
            
            return event_type
    
    # Si aucun type d'événement spécifique n'est trouvé, vérifier les anciens formats
    # (compatibilité avec le code existant)
    event_types = {
        "A2 1D": "EVT_CONNECTION_CLEARED",
        "A2 02": "EVT_ALERTING",
        "A2 03": "EVT_CALL_DELIVERED",
        "A2 04": "EVT_CALL_ESTABLISHED",
        "A2 05": "EVT_CALL_FAILED",
        "A2 06": "EVT_CALL_HELD",
        "A2 07": "EVT_CALL_INFORMATION",
        "A2 08": "EVT_CALL_INITIATED",
        "A2 09": "EVT_CALL_ORIGINATED",
        "A2 0B": "EVT_CALL_RETRIEVED",
        "A2 0C": "EVT_CONFERENCED",
        "A2 0E": "EVT_DIVERTED",
        "A2 0F": "EVT_TRANSFERRED"
    }

    # Vérifier les types d'événements spécifiques (ancien format)
    for hex_code, event_type in event_types.items():
        if hex_code in hex_data:
            return event_type

    # Si aucun type d'événement connu n'est trouvé, retourner UNKNOWN
    return "UNKNOWN"

def handle_keepalive(data):
    """
    Traite un message keepalive et génère la réponse appropriée
    
    Args:
        data (bytes): Données brutes du keepalive
        
    Returns:
        dict: Informations sur le keepalive
        bytes or None: Réponse au keepalive, si nécessaire
    """
    hex_data = bytes_to_hex(data)
    keepalive_info = {
        "type": "KEEPALIVE",
        "raw_hex": hex_data,
        "parsed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    }
    
    # Extraction de l'identifiant d'invocation (nécessaire pour la réponse)
    try:
        invoke_id_pattern = r"02 01 34 05 ([0-9A-F]{2})"
        import re
        id_match = re.search(invoke_id_pattern, hex_data)
        if id_match:
            keepalive_id = id_match.group(1)
            keepalive_info["id"] = keepalive_id
            
            # Génération de la réponse au keepalive
            response = hex_to_bytes(f"00 0D A2 0B 02 02 00 00 30 05 02 01 34 05 {keepalive_id}")
            keepalive_info["response"] = response
            return keepalive_info, response
    except Exception as e:
        logger.error(f"Erreur lors du traitement du keepalive: {e}")
    
    # Si aucune réponse n'est générée
    return keepalive_info, None

def extract_common_info(hex_data):
    """
    Extrait les informations communes à la plupart des événements CSTA
    """
    info = {}
    
    # Extraction de l'identifiant d'invocation
    try:
        invoke_idx = hex_data.find("02 02")
        if invoke_idx != -1:
            invoke_hex = hex_data[invoke_idx+6:invoke_idx+14].replace(" ", "")
            info["invoke_id"] = int(invoke_hex, 16)
    except Exception as e:
        logger.error(f"Erreur extraction invoke_id: {e}")
    
    # Extraction de l'identifiant d'appel (format commun)
    try:
        call_id_idx = hex_data.find("82 02")
        if call_id_idx != -1:
            call_id_hex = hex_data[call_id_idx+6:call_id_idx+14].replace(" ", "")
            info["call_id"] = int(call_id_hex, 16)
    except Exception as e:
        logger.error(f"Erreur extraction call_id: {e}")
    
    # Extraction de l'horodatage (format commun)
    try:
        time_idx = hex_data.find("17 0D")
        if time_idx != -1:
            # Format: YYMMDDhhmmssZ (13 caractères)
            time_str = ""
            for i in range(0, 39, 3):  # 13 caractères × 3 positions hex
                pos = time_idx + 6 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    try:
                        time_str += chr(int(byte_hex, 16))
                    except:
                        break
            
            if len(time_str) >= 12:
                year = f"20{time_str[0:2]}"
                month = time_str[2:4]
                day = time_str[4:6]
                hour = time_str[6:8]
                minute = time_str[8:10]
                second = time_str[10:12]
                
                info["timestamp"] = f"{year}-{month}-{day} {hour}:{minute}:{second}"
    except Exception as e:
        logger.error(f"Erreur extraction timestamp: {e}")
    
    return info

def extract_device_info2(hex_data):
    """
    Extrait les informations sur les appareils impliqués dans l'événement
    """
    devices = {}
    
    # Extraction du numéro appelant (format 63 07 84 05 + numéro ASCII)
    try:
        calling_idx = hex_data.find("63 07 84 05")
        if calling_idx != -1:
            calling_num = ""
            for i in range(0, 15, 3):
                pos = calling_idx + 12 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        calling_num += chr(int(byte_hex, 16))
                    else:
                        break
            if calling_num:
                devices["calling_number"] = calling_num
    except Exception as e:
        logger.error(f"Erreur extraction calling_number: {e}")
    
    # Extraction du numéro appelé (format 82 0B + numéro ASCII)
    try:
        called_num_pattern = "82 0B ([0-9A-F ]+)"
        import re
        called_match = re.search(called_num_pattern, hex_data)
        if called_match:
            called_hex = called_match.group(1).replace(" ", "")
            called_number = ""
            for i in range(0, len(called_hex), 2):
                if i + 2 <= len(called_hex):
                    char_hex = called_hex[i:i+2]
                    char_val = int(char_hex, 16)
                    if 48 <= char_val <= 57:  # Chiffres ASCII
                        called_number += chr(char_val)
            if called_number:
                devices["called_number"] = called_number
    except Exception as e:
        logger.error(f"Erreur extraction called_number: {e}")
    
    # Extraction de l'extension appelée (format 62 07 84 05 + extension ASCII)
    try:
        extension_idx = hex_data.find("62 07 84 05")
        if extension_idx != -1:
            extension = ""
            for i in range(0, 15, 3):
                pos = extension_idx + 12 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        extension += chr(int(byte_hex, 16))
                    else:
                        break
            if extension:
                devices["called_extension"] = extension
    except Exception as e:
        logger.error(f"Erreur extraction called_extension: {e}")
    
    # Extraction du périphérique initiateur (format alternatif)
    try:
        initiator_idx = hex_data.find("55 04 01")
        if initiator_idx != -1:
            # Les codes suivants peuvent varier, rechercher les chiffres ASCII
            initiator = ""
            for i in range(0, 15, 3):
                pos = initiator_idx + 9 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        initiator += chr(int(byte_hex, 16))
                    else:
                        break
            if initiator:
                devices["initiator_device"] = initiator
    except Exception as e:
        logger.error(f"Erreur extraction initiator_device: {e}")
    
    return devices

def extract_device_info(hex_data):
    """
    Extrait les informations sur les appareils impliqués dans l'événement
    """
    devices = {}
    
    # Extraction du numéro appelant (format 63 07 84 05 + numéro ASCII)
    try:
        calling_idx = hex_data.find("63 07 84 05")
        if calling_idx != -1:
            calling_num = ""
            for i in range(0, 15, 3):
                pos = calling_idx + 12 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        calling_num += chr(int(byte_hex, 16))
                    else:
                        break
            if calling_num:
                devices["calling_number"] = calling_num
    except Exception as e:
        logger.error(f"Erreur extraction calling_number: {e}")
    
    # Extraction du numéro appelé (format 82 0B + numéro ASCII) avec meilleure gestion de la limite
    try:
        # Recherche du pattern "82 0B" qui indique le début du numéro appelé
        called_idx = hex_data.find("82 0B")
        if called_idx != -1:
            # Récupérer la longueur réelle de la valeur (dans la structure ASN.1, la longueur est 0B)
            length_hex = int("0B", 16)  # 11 caractères max
            
            # Extraire le numéro appelé
            called_number = ""
            for i in range(0, length_hex * 3, 3):
                pos = called_idx + 6 + i  # +6 pour sauter "82 0B"
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    try:
                        byte_val = int(byte_hex, 16)
                        # Uniquement chiffres, '+', '*', '#' et quelques caractères spéciaux acceptés
                        if (48 <= byte_val <= 57) or byte_val in [43, 42, 35, 32]:
                            called_number += chr(byte_val)
                        else:
                            # Caractère non valide pour un numéro de téléphone, on s'arrête
                            break
                    except ValueError:
                        break
            
            # Normalisation du numéro (supprimer les caractères non souhaités)
            called_number = ''.join(c for c in called_number if c.isdigit() or c in ['+', '*', '#'])
            
            # Correction des préfixes internationaux mal formatés (00 -> +)
            if called_number.startswith("00"):
                called_number = "0" + called_number[2:]
            
            if called_number:
                devices["called_number"] = called_number
    except Exception as e:
        logger.error(f"Erreur extraction called_number: {e}")
    
    # Extraction de l'extension appelée (format 62 07 84 05 + extension ASCII)
    try:
        extension_idx = hex_data.find("62 07 84 05")
        if extension_idx != -1:
            extension = ""
            for i in range(0, 15, 3):
                pos = extension_idx + 12 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        extension += chr(int(byte_hex, 16))
                    else:
                        break
            if extension:
                devices["called_extension"] = extension
    except Exception as e:
        logger.error(f"Erreur extraction called_extension: {e}")
    
    # Extraction du périphérique initiateur (format alternatif)
    try:
        initiator_idx = hex_data.find("55 04 01")
        if initiator_idx != -1:
            # Les codes suivants peuvent varier, rechercher les chiffres ASCII
            initiator = ""
            for i in range(0, 15, 3):
                pos = initiator_idx + 9 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        initiator += chr(int(byte_hex, 16))
                    else:
                        break
            if initiator:
                devices["initiator_device"] = initiator
    except Exception as e:
        logger.error(f"Erreur extraction initiator_device: {e}")
    
    return devices

def extract_connection_info(hex_data):
    """
    Extrait les informations sur l'état de la connexion
    """
    connection = {}
    
    # Extraction de l'état de la connexion (format 64 02 88 XX ou 4E 01 XX)
    try:
        # Format 1: 64 02 88 XX
        conn_state_idx = hex_data.find("64 02 88")
        if conn_state_idx != -1:
            conn_state_hex = hex_data[conn_state_idx+9:conn_state_idx+11]
            conn_state = int(conn_state_hex, 16)
            connection["connection_state"] = conn_state
            connection["connection_state_desc"] = {
                0: "connected",
                1: "alerting",
                2: "held",
                3: "queued",
                4: "disconnected"
            }.get(conn_state, f"unknown({conn_state})")
        
        # Format 2: 4E 01 XX
        conn_state_idx2 = hex_data.find("4E 01")
        if conn_state_idx2 != -1:
            conn_state = int(hex_data[conn_state_idx2+6:conn_state_idx2+8], 16)
            connection["connection_state"] = conn_state
            connection["connection_state_desc"] = {
                0: "null",
                1: "initiated",
                2: "alerting", 
                3: "connected",
                4: "hold",
                5: "queued",
                6: "fail"
            }.get(conn_state, f"unknown({conn_state})")
    except Exception as e:
        logger.error(f"Erreur extraction connection_state: {e}")
    
    # Extraction de la cause (format 0A 01 XX)
    try:
        cause_idx = hex_data.find("0A 01")
        if cause_idx != -1:
            cause_code = int(hex_data[cause_idx+6:cause_idx+8], 16)
            connection["cause_code"] = cause_code
            connection["cause"] = {
                22: "newCall",
                48: "normalClearing",
                11: "callPickup",
                13: "destNotObtainable",
                16: "callBack", 
                3: "newConnection"
            }.get(cause_code, f"unknown({cause_code})")
    except Exception as e:
        logger.error(f"Erreur extraction cause: {e}")
    
    # Extraction du cross reference identifier (format 83 04 XX XX XX XX)
    try:
        xref_idx = hex_data.find("83 04")
        if xref_idx != -1:
            xref_hex = hex_data[xref_idx+6:xref_idx+18].replace(" ", "")
            connection["cross_ref_identifier"] = int(xref_hex, 16)
    except Exception as e:
        logger.error(f"Erreur extraction cross_ref_identifier: {e}")
    
    return connection

def extract_held_info(hex_data):
    """
    Extrait les informations spécifiques à l'événement HELD (mise en attente)
    """
    info = {}
    
    # Les informations communes sont déjà extraites par extract_common_info
    # et extract_device_info. Ici, nous ajoutons les informations spécifiques
    
    # Déterminer qui a mis l'appel en attente
    try:
        holding_device_idx = hex_data.find("63 07 84 05")
        if holding_device_idx != -1:
            holding_device = ""
            for i in range(0, 15, 3):
                pos = holding_device_idx + 12 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        holding_device += chr(int(byte_hex, 16))
                    else:
                        break
            if holding_device:
                info["holding_device"] = holding_device
    except Exception as e:
        logger.error(f"Erreur extraction holding_device: {e}")
    
    return info

def extract_retrieved_info(hex_data):
    """
    Extrait les informations spécifiques à l'événement RETRIEVED (récupération d'appel)
    """
    info = {}
    
    # Déterminer qui a récupéré l'appel
    try:
        retrieving_device_idx = hex_data.find("63 07 84 05")
        if retrieving_device_idx != -1:
            retrieving_device = ""
            for i in range(0, 15, 3):
                pos = retrieving_device_idx + 12 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        retrieving_device += chr(int(byte_hex, 16))
                    else:
                        break
            if retrieving_device:
                info["retrieving_device"] = retrieving_device
    except Exception as e:
        logger.error(f"Erreur extraction retrieving_device: {e}")
    
    return info

def extract_conferenced_info(hex_data):
    """
    Extrait les informations spécifiques à l'événement CONFERENCED (conférence)
    """
    info = {}
    
    # Extraire l'identifiant de la conférence
    try:
        conf_id_idx = hex_data.find("C1 05")  # Format typique pour les IDs de conférence
        if conf_id_idx != -1:
            conf_id_hex = hex_data[conf_id_idx+6:conf_id_idx+16].replace(" ", "")
            info["conference_id"] = int(conf_id_hex, 16)
    except Exception as e:
        logger.error(f"Erreur extraction conference_id: {e}")
    
    # Extraire les participants (peut varier selon l'implémentation)
    # Cette partie est très spécifique à chaque système et format
    
    return info

def extract_diverted_info(hex_data):
    """
    Extrait les informations spécifiques à l'événement DIVERTED (redirection)
    """
    info = {}
    
    # Extraire la destination de la redirection
    try:
        divert_to_idx = hex_data.find("66 07 84 05")  # Format supposé pour l'appareil de redirection
        if divert_to_idx != -1:
            divert_to = ""
            for i in range(0, 15, 3):
                pos = divert_to_idx + 12 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        divert_to += chr(int(byte_hex, 16))
                    else:
                        break
            if divert_to:
                info["diverted_to_device"] = divert_to
    except Exception as e:
        logger.error(f"Erreur extraction diverted_to_device: {e}")
    
    # Extraire le type de redirection
    try:
        divert_type_idx = hex_data.find("67 01")  # Format supposé pour le type de redirection
        if divert_type_idx != -1:
            divert_type = int(hex_data[divert_type_idx+6:divert_type_idx+8], 16)
            info["diversion_type"] = divert_type
            info["diversion_type_desc"] = {
                0: "forward-immediate",
                1: "forward-busy",
                2: "forward-no-answer",
                3: "deflect"
            }.get(divert_type, f"unknown({divert_type})")
    except Exception as e:
        logger.error(f"Erreur extraction diversion_type: {e}")
    
    return info

def extract_transferred_info(hex_data):
    """
    Extrait les informations spécifiques à l'événement TRANSFERRED (transfert)
    """
    info = {}
    
    # Extraire l'appareil qui a effectué le transfert
    try:
        transferring_device_idx = hex_data.find("63 07 84 05")
        if transferring_device_idx != -1:
            transferring_device = ""
            for i in range(0, 15, 3):
                pos = transferring_device_idx + 12 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        transferring_device += chr(int(byte_hex, 16))
                    else:
                        break
            if transferring_device:
                info["transferring_device"] = transferring_device
    except Exception as e:
        logger.error(f"Erreur extraction transferring_device: {e}")
    
    # Extraire l'appareil vers lequel l'appel a été transféré
    try:
        transferred_to_idx = hex_data.find("68 07 84 05")  # Format supposé pour l'appareil de destination
        if transferred_to_idx != -1:
            transferred_to = ""
            for i in range(0, 15, 3):
                pos = transferred_to_idx + 12 + i
                if pos + 2 <= len(hex_data):
                    byte_hex = hex_data[pos:pos+2]
                    if byte_hex in ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]:
                        transferred_to += chr(int(byte_hex, 16))
                    else:
                        break
            if transferred_to:
                info["transferred_to_device"] = transferred_to
    except Exception as e:
        logger.error(f"Erreur extraction transferred_to_device: {e}")
    
    return info

def detect_transfer_sequence(call_id, active_calls):
    """
    Détecte si un appel fait partie d'une séquence de transfert en analysant
    les relations entre les identifiants d'appel et les événements.
    
    Args:
        call_id: L'identifiant de l'appel actuel
        active_calls: Dictionnaire des appels actifs en cours de suivi
    
    Returns:
        dict: Informations sur le transfert si détecté, None sinon
    """
    # Si l'appel n'existe pas dans notre suivi
    if call_id not in active_calls:
        return None
    
    # Récupérer les informations sur l'appel actuel
    current_call = active_calls[call_id]
    
    # Rechercher des indices de transfert
    transfer_info = {
        "is_transfer": False,
        "transfer_type": None,
        "related_calls": [],
    }
    
    # Parcourir tous les appels actifs pour trouver des relations
    for related_id, related_call in active_calls.items():
        # Ignorer l'appel lui-même
        if related_id == call_id:
            continue
        
        # Vérifier si les horodatages sont proches (moins de 5 secondes d'écart)
        if "start_time" in related_call and "start_time" in current_call:
            try:
                current_time = datetime.strptime(current_call["start_time"], "%Y-%m-%d %H:%M:%S")
                related_time = datetime.strptime(related_call["start_time"], "%Y-%m-%d %H:%M:%S")
                time_diff = abs((current_time - related_time).total_seconds())
                
                # Si les appels sont temporellement proches
                if time_diff < 5:
                    # Vérifier des modèles de transfert
                    
                    # Cas 1: Inversion des numéros appelant/appelé
                    if (current_call.get("calling_number") == related_call.get("called_number") and
                        current_call.get("called_number") == related_call.get("calling_number")):
                        transfer_info["is_transfer"] = True
                        transfer_info["transfer_type"] = "attended"  # Transfert supervisé
                        transfer_info["related_calls"].append(related_id)
                    
                    # Cas 2: Appelant commun mais destinations différentes
                    elif current_call.get("calling_number") == related_call.get("calling_number"):
                        if "external_number" in current_call or "external_number" in related_call:
                            transfer_info["is_transfer"] = True
                            transfer_info["transfer_type"] = "external"  # Transfert vers l'extérieur
                            transfer_info["related_calls"].append(related_id)
                    
                    # Cas 3: Appelé commun mais sources différentes (conférence possible)
                    elif current_call.get("called_number") == related_call.get("called_number"):
                        transfer_info["is_transfer"] = True
                        transfer_info["transfer_type"] = "conference_candidate"
                        transfer_info["related_calls"].append(related_id)
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse des relations d'appel: {e}")
    
    # Si aucun transfert n'est détecté
    if not transfer_info["is_transfer"]:
        return None
    
    return transfer_info

def enrich_call_event(event, active_calls):
    """
    Enrichit un événement d'appel avec des informations sur les transferts
    potentiels et les relations entre appels.
    
    Args:
        event: L'événement d'appel à enrichir
        active_calls: Dictionnaire des appels actifs
    
    Returns:
        dict: L'événement enrichi
    """
    # Copie de l'événement pour éviter de modifier l'original
    enriched_event = event.copy()
    
    # Si l'événement a un identifiant d'appel, vérifier les transferts potentiels
    if "call_id" in event:
        transfer_info = detect_transfer_sequence(event["call_id"], active_calls)
        if transfer_info:
            enriched_event["transfer_detected"] = True
            enriched_event["transfer_type"] = transfer_info["transfer_type"]
            enriched_event["related_calls"] = transfer_info["related_calls"]
            
            # Pour les événements NEW_CALL avec transfert potentiel
            if event["type"] == "NEW_CALL" and len(transfer_info["related_calls"]) > 0:
                # Trouver l'appel précédent dans la séquence
                previous_call_id = transfer_info["related_calls"][0]
                if previous_call_id in active_calls:
                    previous_call = active_calls[previous_call_id]
                    
                    # Ajouter des informations contextuelles
                    if "calling_number" in previous_call and "called_number" in previous_call:
                        enriched_event["original_caller"] = previous_call.get("calling_number")
                        enriched_event["original_called"] = previous_call.get("called_number")
                        
                        # Si les rôles sont inversés, c'est probablement un transfert
                        if (enriched_event.get("calling_number") == previous_call.get("called_number") and
                            "called_number" in enriched_event and 
                            enriched_event["called_number"] != previous_call["calling_number"]):
                            enriched_event["transfer_in_progress"] = True
                            
                        # Si l'appelant original est maintenant connecté à un nouveau numéro
                        if (enriched_event.get("calling_number") == previous_call.get("calling_number") and
                            "called_number" in enriched_event and
                            enriched_event["called_number"] != previous_call["called_number"]):
                            enriched_event["transfer_completed"] = True
    
    return enriched_event


# --------------------------------------------------------------------
# Sanitize
# --------------------------------------------------------------------

def sanitize_for_json(obj):
    """
    Parcourt l'objet (dict, list, etc.) et convertit tous les objets bytes
    en chaîne hexadécimale (ou base64 si vous préférez).
    """
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if isinstance(v, bytes):
                # Convertir en hexadécimal
                obj[k] = bytes_to_hex(v)
            elif isinstance(v, (dict, list)):
                # Appel récursif
                sanitize_for_json(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, bytes):
                obj[i] = bytes_to_hex(v)
            elif isinstance(v, (dict, list)):
                sanitize_for_json(v)
    
    return obj


# --------------------------------------------------------------------
# Connexion et surveillance
# --------------------------------------------------------------------
def connect_and_monitor():
    # Liste des événements à suivre
    TRACKED_EVENTS = [
        # Événements du nouveau format CSTA 2 ASN.1
        "NEW_CALL",             # Nouvel appel
        "CALL_CLEARED",         # Appel terminé
        "DELIVERED",            # Appel livré
        "ESTABLISHED",          # Connexion établie
        "HELD",                 # Appel mis en attente
        "RETRIEVED",            # Appel récupéré
        "CONFERENCED",          # Appel mis en conférence
        "DIVERTED",             # Appel redirigé
        "TRANSFERRED",          # Appel transféré
        
        # Événements spécifiques déjà implémentés
        "EVT_SERVICE_INITIATED",
        "EVT_FAILED",
        
        # Événements de compatibilité
        "INCOMING_CALL",
        "CALL_ESTABLISHED",
        "CALL_DIVERTED",
        "CALL_CLEARED"
    ]
    log_csta_event_codes()
    try:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.settimeout(10)

        logger.info(f"Tentative de connexion au PABX {PABX_IP}:{PABX_PORT}")
        client_sock.connect((PABX_IP, PABX_PORT))
        logger.info("Connexion au PABX réussie")

        # Identification
        ident_command = b"\x42"
        logger.info(f"Envoi de l'identification: {bytes_to_hex(ident_command)}")
        client_sock.sendall(ident_command)

        try:
            response = client_sock.recv(1024)
            logger.info(f"Réponse à l'identification: {bytes_to_hex(response)}")

            time.sleep(2)

            # Session
            session_cmd = hex_to_bytes(
                "00 46 60 44 80 02 07 80 A1 07 06 05 2B 0C 00 81 34 BE 35 "
                "28 33 06 07 2B 0C 00 81 5A 81 48 A0 28 30 26 03 02 03 C0 "
                "30 16 80 04 03 E7 B6 48 81 06 02 5F FD 03 FE A0 83 02 06 "
                "C0 84 02 03 F0 30 08 82 02 03 D8 83 02 06 C0"
            )
            logger.info(f"Envoi de la commande session: {bytes_to_hex(session_cmd)}")
            client_sock.sendall(session_cmd)

            try:
                response = client_sock.recv(1024)
                logger.info(f"Réponse à la commande session: {bytes_to_hex(response)}")

                time.sleep(2)

                # StartMonitor + Snapshot
                for device in DEVICES_TO_MONITOR:
                    monitor_cmd = build_start_monitor_cmd(device)
                    logger.info(f"Envoi de Start Monitor pour poste {device}: {bytes_to_hex(monitor_cmd)}")
                    client_sock.sendall(monitor_cmd)
                    try:
                        response = client_sock.recv(1024)
                        logger.info(f"Réponse à Start Monitor ({device}): {bytes_to_hex(response)}")
                    except socket.timeout:
                        logger.warning(f"Pas de réponse à Start Monitor pour {device}")

                    time.sleep(4)


                    snapshot_cmd = build_snapshot_cmd(device)
                    logger.info(f"Envoi de Snapshot pour poste {device}: {bytes_to_hex(snapshot_cmd)}")
                    client_sock.sendall(snapshot_cmd)
                    try:
                        response = client_sock.recv(1024)
                        logger.info(f"Réponse à Snapshot ({device}): {bytes_to_hex(response)}")
                        
                        # Parse and send snapshot response via MQTT
                        snapshot_event = parse_event(response)
                        if snapshot_event:
                            # Add device information to the snapshot event
                            snapshot_event['monitored_device'] = device
                            
                            # Send snapshot response to MQTT
                            send_mqtt_event({
                                "type": "SNAPSHOT_RESPONSE",
                                "device": device,
                                "details": snapshot_event
                            })
                    except socket.timeout:
                        logger.warning(f"Pas de réponse au Snapshot pour {device}")
                        logger.info(f"Fin du monitoring pour le poste {device}, attente avant l'appareil suivant...")
                        time.sleep(4)                        

                client_sock.setblocking(False)
                invoke_id = 1
                last_keepalive_time = time.time()

                logger.info("Début de la surveillance des événements...")

                while True:
                    # keepalive périodique
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

                    # Lecture des événements
                    try:
                        data = client_sock.recv(4096)
                        if data:
                            # Convertir les données en hexadécimal pour le log
                            hex_data = bytes_to_hex(data)
                            
                            # Détecter le type d'événement
                            event_type = detect_csta_event_type(hex_data)
                            
                            # Traitement spécial pour les keepalives
                            if event_type == "KEEPALIVE":
                                keepalive_info, response = handle_keepalive(data)
                                if response:
                                    try:
                                        client_sock.sendall(response)
                                        logger.debug(f"Réponse au keepalive envoyée: {bytes_to_hex(response)}")
                                    except socket.error as e:
                                        logger.error(f"Erreur lors de l'envoi de la réponse au keepalive: {e}")
                                        break
                                # On n'analyse pas davantage les keepalives
                                continue
                            
                            # Pour les autres types d'événements, analyser complètement
                            event_info = parse_event(data)
                            
                            # Log du message hex complet pour les types d'événements suivis
                            if event_type in TRACKED_EVENTS:
                                log_analyzed_event(event_type, hex_data)

                            logger.info(f"Événement reçu: {event_type}")
                            
                            # Suivi d'appel pour tous les types d'événements pris en charge
                            if event_type in TRACKED_EVENTS:
                                # Enrichir l'événement avec les informations de transfert potentielles
                                enriched_event = enrich_call_event(event_info, active_calls)
                                track_call(enriched_event)
                                # Publication sur MQTT de l'événement enrichi
                                send_mqtt_event(enriched_event)
                            else:
                                # Publication sur MQTT des autres événements (sauf keepalives)
                                if event_type != "UNKNOWN" and event_type != "KEEPALIVE":
                                    send_mqtt_event(event_info)

                                logger.info(f"Événement reçu: {bytes_to_hex(data)}")

                                # Suivi d'appel pour tous les types d'événements pris en charge
                                if event_info["type"] in TRACKED_EVENTS:
                                    # Enrichir l'événement avec les informations de transfert potentielles
                                    enriched_event = enrich_call_event(event_info, active_calls)
                                    track_call(enriched_event)
                                    # Publication sur MQTT de l'événement enrichi
                                    send_mqtt_event(enriched_event)
                                else:
                                    # Publication sur MQTT des autres événements
                                    send_mqtt_event(event_info)

                                # Réponse au keepalive
                                if event_info.get("type") == "KEEPALIVE":
                                    try:
                                        response_keepalive = event_info.get("response")
                                        if response_keepalive:
                                            client_sock.sendall(response_keepalive)
                                            logger.debug(f"Réponse au keepalive envoyée: {bytes_to_hex(response_keepalive)}")
                                    except socket.error as e:
                                        logger.error(f"Erreur lors de l'envoi de la réponse au keepalive: {e}")
                                        break

                    except (socket.error, BlockingIOError):
                        pass

                    time.sleep(0.1)

                logger.info(f"Fin de la session de surveillance (durée: {SESSION_TIME} secondes)")

            except socket.timeout:
                logger.warning("Pas de réponse à la commande session")
        except socket.timeout:
            logger.warning("Pas de réponse à l'identification")

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

# Liste des événements à suivre
TRACKED_EVENTS = [
    # Événements du nouveau format CSTA 2 ASN.1
    "NEW_CALL",             # Nouvel appel
    "CALL_CLEARED",         # Appel terminé
    "DELIVERED",            # Appel livré
    "ESTABLISHED",          # Connexion établie
    "HELD",                 # Appel mis en attente
    "RETRIEVED",            # Appel récupéré
    "CONFERENCED",          # Appel mis en conférence
    "DIVERTED",             # Appel redirigé
    "TRANSFERRED",          # Appel transféré
    
    # Événements spécifiques déjà implémentés
    "EVT_SERVICE_INITIATED",
    "EVT_FAILED",
    
    # Événements de compatibilité
    "INCOMING_CALL",
    "CALL_ESTABLISHED",
    "CALL_DIVERTED",
    "CALL_CLEARED"
]

def log_csta_event_codes():
    """
    Affiche dans la console les codes hexadécimaux pour chaque type d'événement CSTA suivi
    """
    # Table de correspondance entre les types d'événements et leurs codes hexadécimaux
    event_hex_codes = {
        # Événements standard CSTA 2 ASN.1
        "NEW_CALL": "02 01 15",         # Code le plus courant pour NEW_CALL
        "CALL_CLEARED": "02 01 01",     # Appel terminé
        "DELIVERED": "02 01 03",        # Appel livré
        "ESTABLISHED": "02 01 04",      # Connexion établie
        "HELD": "02 01 06",             # Appel mis en attente
        "RETRIEVED": "02 01 0B",        # Appel récupéré
        "CONFERENCED": "02 01 0C",      # Appel mis en conférence
        "DIVERTED": "02 01 0E",         # Appel redirigé
        "TRANSFERRED": "02 01 0F",      # Appel transféré
        
        # Événements spécifiques
        "EVT_SERVICE_INITIATED": "02 01 15 + patterns spécifiques", # Partage le code avec NEW_CALL
        "EVT_FAILED": "02 01 15 + 4E 01 06 + 0A 01 0D",             # Partage le code avec NEW_CALL
        
        # Événements de compatibilité (anciens formats)
        "INCOMING_CALL": "Format personalisé",
        "CALL_ESTABLISHED": "A2 04",
        "CALL_DIVERTED": "A2 0E",
        "CALL_CLEARED": "A2 1D"
    }
    
    # Exemples d'événements complets (premiers octets)
    event_examples = {
        "NEW_CALL": "00 9E A1 81 9B 02 02 12 BB 02 01 15 30 81 91 55 04 01 35...",
        "EVT_SERVICE_INITIATED": "00 52 A1 50 02 02 4C B7 02 01 15 30 47 55 04 01...",
        "EVT_FAILED": "00 62 A1 60 02 02 4C BD 02 01 15 30 57 55 04 01..."
    }
    
    # Afficher les codes hexadécimaux pour chaque type d'événement suivi
    logger.info("=== CODES HEXADÉCIMAUX DES ÉVÉNEMENTS CSTA SUIVIS ===")
    for event_type in TRACKED_EVENTS:
        hex_code = event_hex_codes.get(event_type, "Code inconnu")
        example = event_examples.get(event_type, "")
        
        logger.info(f"{event_type}: {hex_code}")
        
        if example:
            logger.info(f"    Exemple: {example}")
        
        logger.info("---")
    
    logger.info("=== FIN DES CODES HEXADÉCIMAUX ===")
# --------------------------------------------------------------------
# Boucle principale
# --------------------------------------------------------------------

# Ajouter ces fonctions d'export avant la fonction main()

def export_event_examples_to_file(filename="csta_event_examples.log"):
    """
    Exporte tous les exemples d'événements collectés dans un fichier
    
    Args:
        filename (str): Nom du fichier où enregistrer les exemples
    """
    try:
        with open(filename, 'w') as f:
            f.write("=== EXEMPLES COMPLETS PAR TYPE D'ÉVÉNEMENT CSTA ===\n\n")
            
            for event_type, hex_data in event_full_examples.items():
                f.write(f"\n\n=== TYPE: {event_type} ===\n")
                f.write(f"{hex_data}\n")
                f.write("=" * 50 + "\n")
            
            f.write("\n=== FIN DES EXEMPLES COMPLETS ===\n")
        
        logger.info(f"Exemples d'événements exportés avec succès dans {filename}")
        
    except Exception as e:
        logger.error(f"Erreur lors de l'exportation des exemples d'événements: {e}")

# Signal handler pour exporter les logs automatiquement à la fin du programme
import signal

def signal_handler(sig, frame):
    """Gestionnaire de signal pour exporter les logs avant de quitter"""
    print_all_event_examples()
    export_event_examples_to_file()
    logger.info("Programme arrêté par l'utilisateur")
    sys.exit(0)

# Fonction pour déclencher l'exportation à la demande (peut être appelée via une API ou un autre mécanisme)
def trigger_export_logs():
    """Déclenche l'exportation des logs d'événements collectés"""
    logger.info("Exportation des logs d'événements déclenchée manuellement")
    print_all_event_examples()
    export_event_examples_to_file()
    return True

# Enregistrer le gestionnaire de signal pour SIGINT (Ctrl+C)
# Cette ligne doit être placée après la définition de signal_handler, mais avant les autres appels de fonction
signal.signal(signal.SIGINT, signal_handler)
def main():
    global mqtt_client
    mqtt_client = init_mqtt_client()

    logger.info(f"Démarrage de l'écouteur CSTA pour les postes : {', '.join(DEVICES_TO_MONITOR)}")

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



# Signal handler pour exporter les logs automatiquement à la fin du programme
import signal

def signal_handler(sig, frame):
    """Gestionnaire de signal pour exporter les logs avant de quitter"""
    print_all_event_examples()
    export_event_examples_to_file()
    logger.info("Programme arrêté par l'utilisateur")
    sys.exit(0)

# Enregistrer le gestionnaire de signal pour SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, signal_handler)

# Fonction pour déclencher l'exportation à la demande (peut être appelée via une API ou un autre mécanisme)
def trigger_export_logs():
    """Déclenche l'exportation des logs d'événements collectés"""
    logger.info("Exportation des logs d'événements déclenchée manuellement")
    print_all_event_examples()
    export_event_examples_to_file()
    return True

def analyze_event_structure(hex_data):
    """
    Analyse la structure d'un message CSTA en hexadécimal
    et retourne une description de ses principales sections
    
    Args:
        hex_data (str): Données hexadécimales du message
        
    Returns:
        dict: Structure du message avec ses sections principales
    """
    structure = {
        "total_length": "",
        "invoke_id": "",
        "event_code": "",
        "sections": []
    }
    
    # Extraire la longueur totale (premiers octets)
    if len(hex_data) >= 5:
        structure["total_length"] = hex_data[0:5]
    
    # Rechercher l'identifiant d'invocation
    invoke_idx = hex_data.find("02 02")
    if invoke_idx != -1:
        structure["invoke_id"] = hex_data[invoke_idx:invoke_idx+14]
    
    # Rechercher le code d'événement
    event_code_idx = hex_data.find("02 01")
    if event_code_idx != -1:
        structure["event_code"] = hex_data[event_code_idx:event_code_idx+8]
    
    # Analyser les sections spécifiques selon le type d'événement
    if "02 01 15" in hex_data:  # NEW_CALL, SERVICE_INITIATED ou FAILED
        if "4E 01 06" in hex_data:  # EVT_FAILED
            structure["sections"].append({
                "name": "State",
                "value": "4E 01 06 (failure)",
                "position": hex_data.find("4E 01 06")
            })
        
        # Rechercher les appareils
        calling_idx = hex_data.find("63 07 84 05")
        if calling_idx != -1:
            extracted = extract_ascii_from_hex(hex_data, calling_idx + 12)
            structure["sections"].append({
                "name": "Calling Device",
                "value": extracted,
                "position": calling_idx
            })
        
        called_idx = hex_data.find("62 07 84 05")
        if called_idx != -1:
            extracted = extract_ascii_from_hex(hex_data, called_idx + 12)
            structure["sections"].append({
                "name": "Called Device",
                "value": extracted,
                "position": called_idx
            })
        
        # Rechercher l'horodatage
        time_idx = hex_data.find("17 0D")
        if time_idx != -1:
            structure["sections"].append({
                "name": "Timestamp",
                "value": hex_data[time_idx:time_idx+50],
                "position": time_idx
            })
    
    # Ajouter d'autres analyses spécifiques pour d'autres types d'événements
    elif "02 01 01" in hex_data:  # CALL_CLEARED
        cause_idx = hex_data.find("0A 01")
        if cause_idx != -1:
            cause_code = hex_data[cause_idx+6:cause_idx+8]
            structure["sections"].append({
                "name": "Clearing Cause",
                "value": f"0A 01 {cause_code}",
                "position": cause_idx
            })
    
    # ... autres types d'événements ...
    
    return structure



def log_full_hex_message(event_type, hex_data):
    """
    Enregistre un message hexadécimal complet pour un type d'événement
    Si c'est le premier exemple rencontré pour ce type, l'enregistre dans le dictionnaire
    """
    if event_type not in event_full_examples:
        event_full_examples[event_type] = hex_data
        logger.info(f"=== NOUVEL EXEMPLE COMPLET POUR {event_type} ===")
        logger.info(f"{hex_data}")
        logger.info("=" * 50)

def print_all_event_examples():
    """
    Affiche tous les exemples complets enregistrés
    """
    logger.info("=== EXEMPLES COMPLETS PAR TYPE D'ÉVÉNEMENT CSTA ===")
    for event_type, hex_data in event_full_examples.items():
        logger.info(f"\n\n=== TYPE: {event_type} ===")
        logger.info(f"{hex_data}")
        logger.info("=" * 50)
    logger.info("=== FIN DES EXEMPLES COMPLETS ===")



def log_analyzed_event(event_type, hex_data):
    """
    Enregistre un message avec sa structure analysée
    
    Args:
        event_type (str): Type d'événement
        hex_data (str): Données hexadécimales du message
    """
    structure = analyze_event_structure(hex_data)
    
    # Formatter l'analyse pour le log
    analysis = f"\n=== ANALYSE DE L'ÉVÉNEMENT {event_type} ===\n"
    analysis += f"Longueur totale: {structure['total_length']}\n"
    analysis += f"Identifiant d'invocation: {structure['invoke_id']}\n"
    analysis += f"Code d'événement: {structure['event_code']}\n"
    analysis += "\nSections détectées:\n"
    
    for section in structure["sections"]:
        analysis += f"- {section['name']}: {section['value']} (position {section['position']})\n"
    
    analysis += "\nDonnées hexadécimales complètes:\n"
    analysis += hex_data
    analysis += f"\n{'=' * 50}\n"
    
    # Enregistrer dans le log
    logger.info(analysis)
    
    # Enregistrer aussi l'exemple complet
    if event_type not in event_full_examples:
        event_full_examples[event_type] = hex_data

def cleanup_old_calls():
    """
    Nettoie les appels terminés depuis longtemps de la structure active_calls
    pour éviter une consommation excessive de mémoire.
    Cette fonction est appelée périodiquement.
    """
    now = datetime.now()
    calls_to_remove = []
    
    for call_id, call in active_calls.items():
        # Vérifier si l'appel a un statut de fin (completed, failed)
        if call.get("status") in ["completed", "failed"]:
            # Si l'appel a une date de fin, vérifier qu'elle date d'au moins 1 heure
            if "end_time" in call:
                try:
                    end_time = datetime.strptime(call["end_time"], "%Y-%m-%d %H:%M:%S")
                    # Si l'appel est terminé depuis plus d'une heure
                    if (now - end_time).total_seconds() > 3600:  # 3600 secondes = 1 heure
                        calls_to_remove.append(call_id)
                except:
                    # Erreur de format de date, on garde l'appel
                    pass
        # Vérifier également les appels "zombie" (pas de statut final mais très anciens)
        elif "start_time" in call:
            try:
                start_time = datetime.strptime(call["start_time"], "%Y-%m-%d %H:%M:%S")
                # Si l'appel a été créé il y a plus de 24 heures
                if (now - start_time).total_seconds() > 86400:  # 86400 secondes = 24 heures
                    # Forcer la terminaison de cet appel
                    logger.warning(f"Appel 'zombie' détecté - ID: {call_id}, début: {call['start_time']}, statut: {call.get('status')}")
                    call["status"] = "completed_auto"
                    call["end_time"] = now.strftime("%Y-%m-%d %H:%M:%S")
                    call["duration"] = calculate_duration(call["start_time"], call["end_time"])
                    
                    # Générer un historique pour cet appel
                    log_call_history(call)
                    send_call_history_mqtt(call)
                    
                    # Marquer pour suppression
                    calls_to_remove.append(call_id)
            except:
                # Erreur de format de date, on ignore
                pass
    
    # Supprimer les appels identifiés
    for call_id in calls_to_remove:
        del active_calls[call_id]
    
    if calls_to_remove:
        logger.info(f"Nettoyage des appels terminés: {len(calls_to_remove)} appels supprimés")
        logger.info(f"Nombre d'appels actifs restants: {len(active_calls)}")

# Pour activer le nettoyage périodique, ajoutez ce code dans connect_and_monitor(),
# juste après la définition des variables invoke_id et last_keepalive_time:

last_cleanup_time = time.time()
CLEANUP_INTERVAL = 3600  # Nettoyer une fois par heure (3600 secondes)

# Puis dans la boucle principale, ajoutez:

# Nettoyage périodique des appels terminés
current_time = time.time()
if current_time - last_cleanup_time >= CLEANUP_INTERVAL:
    cleanup_old_calls()
    last_cleanup_time = current_time