#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSTA Monitor - Application de surveillance des appels téléphoniques via le protocole CSTA
Conçu pour les PABX Alcatel OXE

Version: 3.0.0
Date: Mars 2025
"""
print("Démarrage du test de CSTA Monitor...")

print("1. Importation des bibliothèques standard...")

import socket
import sys
import time
import logging
import binascii
import json
import signal
import re
import os
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Union

print("2. Importation des dépendances externes...")
try:
    import paho.mqtt.client as mqtt
    print("   - Paho MQTT importé avec succès")
except ImportError as e:
    print(f"   - ERREUR: Impossible d'importer paho.mqtt: {e}")
    print("   - Installez-le avec: pip3 install paho-mqtt")
    sys.exit(1)

print("3. Vérification de l'accès aux dossiers...")
try:
    os.makedirs("logs", exist_ok=True)
    print("   - Dossier 'logs' créé/vérifié avec succès")
    with open("logs/test.log", "w") as f:
        f.write("Test d'écriture")
    print("   - Test d'écriture dans logs/test.log réussi")
except PermissionError as e:
    print(f"   - ERREUR: Problème de permissions sur le dossier 'logs': {e}")
    print("   - Créez manuellement le dossier avec: mkdir -p logs; chmod 777 logs")
    sys.exit(1)

print("4. Test connexion réseau...")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    result = s.connect_ex(("10.134.100.113", 2555))
    if result == 0:
        print("   - Connexion à 10.134.100.113:2555 possible")
    else:
        print(f"   - AVERTISSEMENT: Impossible de se connecter à 10.134.100.113:2555 (code {result})")
        print("   - Vérifiez que le PABX est accessible depuis ce réseau")
    s.close()
except Exception as e:
    print(f"   - ERREUR lors du test réseau: {e}")

print("Tous les tests préliminaires sont passés. Le script devrait fonctionner.")
    

# -----------------------------------------------------------------------------
# Configuration du logging avec rotation de fichiers
# -----------------------------------------------------------------------------
from logging.handlers import RotatingFileHandler

# Création du dossier de logs s'il n'existe pas
os.makedirs("logs", exist_ok=True)

# Configuration du logger principal
logger = logging.getLogger("csta_monitor")
logger.setLevel(logging.INFO)

# Handler pour fichier avec rotation (10 fichiers de 5Mo max)
file_handler = RotatingFileHandler(
    "logs/csta_monitor.log", 
    maxBytes=5*1024*1024,  # 5 Mo
    backupCount=10
)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Handler pour console
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Ajout des handlers au logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Création d'un logger spécifique pour les événements (pour faciliter l'analyse)
event_logger = logging.getLogger("csta_events")
event_logger.setLevel(logging.INFO)
event_file_handler = RotatingFileHandler(
    "logs/csta_events.log", 
    maxBytes=10*1024*1024,  # 10 Mo
    backupCount=20
)
event_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
event_logger.addHandler(event_file_handler)

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

class Config:
    """Configuration centralisée de l'application"""
    
    # Configuration CSTA
    PABX_IP = "10.134.100.113"
    PABX_PORT = 2555
    
    # Liste des postes à surveiller (par PABX)
    DEVICES_TO_MONITOR = [
        "24101", "24102", "24103", "24104", "24105",
        "24119", "24120", "24151", "24152", "24153"
    ]
    
    DEVICES_TO_MONITOR_CHU = [
        "29535", "29707", "29538", "29537", "75219", "14000", "29500"
    ]
    
    # Configuration de la session
    RECONNECT_DELAY = 3     # Délai avant reconnexion en secondes
    SESSION_DURATION = 300   # Durée maximale d'une session en secondes
    KEEPALIVE_INTERVAL = 30  # Intervalle d'envoi des keepalives en secondes
    
    # Configuration MQTT
    MQTT_BROKER = "10.208.4.11"
    MQTT_PORT = 1883
    MQTT_TOPIC = "pabx/csta/monitoring"
    MQTT_USER = "smallfoot"
    MQTT_PASSWORD = "mdpsfi"
    
    # Délai de nettoyage des appels terminés 
    CLEANUP_INTERVAL = 3600  # Nettoyage des appels terminés (1 heure) 
    
    # États de connexion CSTA
    CONNECTION_STATES = {
        0: "null",
        1: "initiated",
        2: "alerting", 
        3: "connected",
        4: "hold",
        5: "queued",
        6: "fail"
    }
    
    # Codes de cause CSTA
    CAUSE_CODES = {
        22: "newCall", 
        48: "normalClearing",
        11: "callPickup",
        13: "destNotObtainable",
        16: "callBack", 
        3: "newConnection",
        44: "makeCall",
        46: "networkSignal"
    }
    
    # Types d'événements à tracker
    TRACKED_EVENTS = [
        # Événements standard CSTA
        "NEW_CALL", "CALL_CLEARED", "DELIVERED", "ESTABLISHED",
        "HELD", "RETRIEVED", "CONFERENCED", "DIVERTED", "TRANSFERRED",
        
        # Événements spécifiques
        "EVT_SERVICE_INITIATED", "EVT_FAILED",
        
        # Événements de compatibilité
        "INCOMING_CALL", "CALL_ESTABLISHED", "CALL_DIVERTED",
    ]


# -----------------------------------------------------------------------------
# Classe principale du moniteur CSTA
# -----------------------------------------------------------------------------

class CSTAMonitor:
    """
    Classe principale pour la surveillance des événements CSTA.
    Gère la connexion, le parsing des événements et leur suivi.
    """
    
    def __init__(self):
        """Initialisation du moniteur CSTA"""
        self.active_calls = {}  # Dictionnaire des appels actifs
        self.event_examples = {}  # Exemples d'événements pour documentation
        self.mqtt_client = None
        self.socket = None
        self.last_keepalive_time = 0
        self.last_cleanup_time = 0
        self.invoke_id = 1
        
        # Connexion au broker MQTT
        self._init_mqtt()
        
        # Configuration des gestionnaires de signaux
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _init_mqtt(self) -> None:
        """Initialisation de la connexion MQTT"""
        try:
            self.mqtt_client = mqtt.Client()
            self.mqtt_client.username_pw_set(Config.MQTT_USER, Config.MQTT_PASSWORD)
            self.mqtt_client.connect(Config.MQTT_BROKER, Config.MQTT_PORT, 60)
            self.mqtt_client.loop_start()
            logger.info(f"Connexion MQTT établie sur {Config.MQTT_BROKER}:{Config.MQTT_PORT}")
        except Exception as e:
            logger.error(f"Erreur de connexion MQTT: {e}")
            self.mqtt_client = None
    
    def _signal_handler(self, sig, frame) -> None:
        """Gestionnaire de signaux pour terminer proprement"""
        logger.info("Signal d'arrêt reçu, arrêt en cours...")
        self.export_event_examples()
        
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        logger.info("Arrêt du moniteur CSTA terminé")
        sys.exit(0)
    
    def run(self) -> None:
        """Démarrage du moniteur avec reconnexion automatique"""
        logger.info(f"Démarrage du moniteur CSTA pour les postes: {', '.join(Config.DEVICES_TO_MONITOR)}")
        
        while True:
            try:
                success = self.connect_and_monitor()
                if success:
                    logger.info(f"Session terminée normalement, reconnexion dans {Config.RECONNECT_DELAY} secondes")
                else:
                    logger.warning(f"Session terminée avec erreur, reconnexion dans {Config.RECONNECT_DELAY} secondes")
                time.sleep(Config.RECONNECT_DELAY)
            except Exception as e:
                logger.error(f"Erreur inattendue: {e}")
                time.sleep(Config.RECONNECT_DELAY)
    
    def connect_and_monitor(self) -> bool:
        """
        Établit la connexion au PABX et démarre la surveillance.
        
        Returns:
            bool: True si la session s'est terminée normalement, False sinon
        """
        try:
            # Création de la socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            
            # Connexion au PABX
            logger.info(f"Connexion au PABX {Config.PABX_IP}:{Config.PABX_PORT}")
            self.socket.connect((Config.PABX_IP, Config.PABX_PORT))
            logger.info("Connexion établie")
            
            # Identification
            ident_command = b"\x42"
            logger.info(f"Envoi de l'identification: {self.bytes_to_hex(ident_command)}")
            self.socket.sendall(ident_command)
            
            response = self._receive_with_timeout()
            if not response:
                logger.warning("Pas de réponse à l'identification")
                return False
            
            logger.info(f"Réponse à l'identification: {self.bytes_to_hex(response)}")
            time.sleep(2)
            
            # Établissement de la session
            session_cmd = self.hex_to_bytes(
                "00 46 60 44 80 02 07 80 A1 07 06 05 2B 0C 00 81 "
                "34 BE 35 28 33 06 07 2B 0C 00 81 5A 81 48 A0 28 "
                "30 26 03 02 03 C0 30 16 80 04 03 E7 B6 48 81 06 "
                "02 5F FD 03 FE A0 83 02 06 C0 84 02 03 F0 30 08 "
                "82 02 03 D8 83 02 06 C0"
            )
            
            logger.info(f"Envoi de la commande de session")
            self.socket.sendall(session_cmd)
            
            response = self._receive_with_timeout()
            if not response:
                logger.warning("Pas de réponse à la commande de session")
                return False
            
            logger.info(f"Réponse à la commande de session: {self.bytes_to_hex(response)}")
            time.sleep(2)
            
            # Démarrage de la surveillance pour chaque poste
            for device in Config.DEVICES_TO_MONITOR:
                self._start_monitoring_device(device)
            
            # Passage en mode non-bloquant pour la boucle principale
            self.socket.setblocking(False)
            
            # Initialisation des compteurs
            self.invoke_id = 1
            self.last_keepalive_time = time.time()
            self.last_cleanup_time = time.time()
            
            logger.info("Début de la surveillance des événements...")
            
            # Boucle principale
            while True:
                current_time = time.time()
                
                # Envoi périodique de keepalive
                if current_time - self.last_keepalive_time >= Config.KEEPALIVE_INTERVAL:
                    self._send_keepalive()
                
                # Nettoyage périodique des appels terminés
                if current_time - self.last_cleanup_time >= Config.CLEANUP_INTERVAL:
                    self._cleanup_old_calls()
                    self.last_cleanup_time = current_time
                
                # Réception des événements
                try:
                    data = self.socket.recv(4096)
                    if data:
                        self._process_received_data(data)
                except (socket.error, BlockingIOError):
                    pass
                
                # Petite pause pour éviter de surcharger le CPU
                time.sleep(0.1)
            
        except socket.error as e:
            logger.error(f"Erreur de socket: {e}")
            return False
        finally:
            if self.socket:
                try:
                    self.socket.close()
                    self.socket = None
                except:
                    pass
            
            return True
    
    def _receive_with_timeout(self) -> Optional[bytes]:
        """
        Reçoit des données avec timeout et gestion d'erreur
        
        Returns:
            Optional[bytes]: Données reçues ou None en cas d'erreur
        """
        try:
            return self.socket.recv(1024)
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Erreur de réception: {e}")
            return None
    
    def _start_monitoring_device(self, device: str) -> None:
        """
        Démarre la surveillance d'un poste spécifique
        
        Args:
            device: Numéro du poste à surveiller
        """
        # Envoi de la commande StartMonitor
        monitor_cmd = self._build_start_monitor_cmd(device)
        logger.info(f"Envoi de StartMonitor pour le poste {device}")
        self.socket.sendall(monitor_cmd)
        
        response = self._receive_with_timeout()
        if response:
            logger.info(f"Réponse StartMonitor ({device}): {self.bytes_to_hex(response)}")
        else:
            logger.warning(f"Pas de réponse à StartMonitor pour {device}")
        
        time.sleep(1)  # Pause pour éviter de saturer le PABX
        
        # Envoi de la commande Snapshot
        snapshot_cmd = self._build_snapshot_cmd(device)
        logger.info(f"Envoi de Snapshot pour le poste {device}")
        self.socket.sendall(snapshot_cmd)
        
        response = self._receive_with_timeout()
        if response:
            logger.info(f"Réponse Snapshot ({device}): {self.bytes_to_hex(response)}")
            # Traitement de la réponse du snapshot
            snapshot_event = self.parse_event(response)
            if snapshot_event:
                snapshot_event['monitored_device'] = device
                self.send_mqtt_event({
                    "type": "SNAPSHOT_RESPONSE",
                    "device": device,
                    "details": snapshot_event
                })
        else:
            logger.warning(f"Pas de réponse à Snapshot pour {device}")
        
        # Pause entre les postes
        time.sleep(1)
    
    def _send_keepalive(self) -> None:
        """Envoie un message keepalive au PABX"""
        try:
            keepalive = self._format_keepalive(self.invoke_id)
            logger.debug(f"Envoi keepalive (ID: {self.invoke_id:04X})")
            self.socket.sendall(keepalive)
            self.last_keepalive_time = time.time()
            self.invoke_id = (self.invoke_id + 1) % 0xFFFF
        except socket.error as e:
            logger.error(f"Erreur lors de l'envoi du keepalive: {e}")
    
    def _process_received_data(self, data: bytes) -> None:
        """
        Traite les données reçues du PABX
        
        Args:
            data: Données brutes reçues
        """
        # Conversion en format hexadécimal pour analyse
        hex_data = self.bytes_to_hex(data)
        
        # Détection du type d'événement
        event_type = self._detect_csta_event_type(hex_data)
        
        # Traitement spécial pour les keepalives
        if event_type == "KEEPALIVE":
            keepalive_info, response = self._handle_keepalive(data)
            if response:
                try:
                    self.socket.sendall(response)
                    logger.debug(f"Réponse au keepalive envoyée")
                except socket.error as e:
                    logger.error(f"Erreur lors de l'envoi de la réponse au keepalive: {e}")
            return
        
        # Pour les autres types d'événements
        logger.info(f"Événement reçu: {event_type}")
        
        # Analyse complète de l'événement
        event_info = self.parse_event(data)
        
        # Log de l'événement en format analysé
        if event_type in Config.TRACKED_EVENTS:
            self._log_analyzed_event(event_type, hex_data)
        
        # Suivi d'appel pour les événements pertinents
        if event_type in Config.TRACKED_EVENTS:
            # Enrichir l'événement avec les informations de transfert
            enriched_event = self._enrich_call_event(event_info)
            self._track_call(enriched_event)
            # Publication sur MQTT
            self.send_mqtt_event(enriched_event)
        elif event_type != "UNKNOWN":
            # Publication sur MQTT des autres événements (sauf UNKNOWN)
            self.send_mqtt_event(event_info)
    
    def _cleanup_old_calls(self) -> None:
        """Nettoie les appels terminés depuis longtemps"""
        now = datetime.now()
        calls_to_remove = []
        
        for call_id, call in self.active_calls.items():
            # Vérifier les appels terminés depuis plus d'une heure
            if call.get("status") in ["completed", "failed"]:
                if "end_time" in call:
                    try:
                        end_time = datetime.strptime(call["end_time"], "%Y-%m-%d %H:%M:%S")
                        if (now - end_time).total_seconds() > 3600:
                            calls_to_remove.append(call_id)
                    except Exception:
                        pass
            
            # Vérifier les appels "zombie" (commencés il y a plus de 24h sans fin)
            elif "start_time" in call:
                try:
                    start_time = datetime.strptime(call["start_time"], "%Y-%m-%d %H:%M:%S")
                    if (now - start_time).total_seconds() > 86400:
                        # Forcer la terminaison
                        logger.warning(f"Appel 'zombie' détecté - ID: {call_id}, début: {call['start_time']}")
                        call["status"] = "completed_auto"
                        call["end_time"] = now.strftime("%Y-%m-%d %H:%M:%S")
                        call["duration"] = self._calculate_duration(call["start_time"], call["end_time"])
                        
                        # Générer un historique
                        self._log_call_history(call)
                        self._send_call_history_mqtt(call)
                        calls_to_remove.append(call_id)
                except Exception:
                    pass
        
        # Suppression des appels identifiés
        for call_id in calls_to_remove:
            del self.active_calls[call_id]
        
        if calls_to_remove:
            logger.info(f"Nettoyage: {len(calls_to_remove)} appels supprimés, {len(self.active_calls)} restants")
    
    # -------------------------------------------------------------------------
    # Méthodes de suivi des appels
    # -------------------------------------------------------------------------
    
    def _track_call(self, event: Dict[str, Any]) -> None:
        """
        Suit le cheminement d'un appel à travers différents événements CSTA
        
        Args:
            event: Événement CSTA analysé
        """
        if not event or "type" not in event or "call_id" not in event:
            return

        call_id = event["call_id"]
        event_type = event["type"]
        timestamp = event.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Création d'un nouvel appel si nécessaire
        if call_id not in self.active_calls:
            self.active_calls[call_id] = {
                "call_id": call_id,
                "start_time": timestamp,
                "events": [],
                "status": "new"
            }

        # Ajout de l'événement à l'historique
        self.active_calls[call_id]["events"].append({
            "type": event_type,
            "timestamp": timestamp,
            "details": event
        })

        # Mise à jour selon le type d'événement
        if event_type == "NEW_CALL":
            self._process_new_call_event(call_id, event, timestamp)
        
        elif event_type == "EVT_SERVICE_INITIATED":
            self._process_service_initiated_event(call_id, event)
        
        elif event_type == "EVT_FAILED":
            self._process_failed_event(call_id, event, timestamp)
        
        elif event_type == "DELIVERED":
            self._process_delivered_event(call_id, event)
        
        elif event_type == "ESTABLISHED":
            self._process_established_event(call_id, event, timestamp)
        
        elif event_type == "HELD":
            self._process_held_event(call_id, event, timestamp)
        
        elif event_type == "RETRIEVED":
            self._process_retrieved_event(call_id, event, timestamp)
        
        elif event_type == "DIVERTED":
            self._process_diverted_event(call_id, event, timestamp)
        
        elif event_type == "CONFERENCED":
            self._process_conferenced_event(call_id, event, timestamp)
        
        elif event_type == "TRANSFERRED":
            self._process_transferred_event(call_id, event, timestamp)
        
        elif event_type in ["CALL_CLEARED", "EVT_CONNECTION_CLEARED"]:
            self._process_call_cleared_event(call_id, event, timestamp)
    
    def _process_new_call_event(self, call_id: Union[str, int], event: Dict[str, Any], timestamp: str) -> None:
        """Traite un événement de nouvel appel"""
        self.active_calls[call_id]["status"] = "new"
        self.active_calls[call_id]["calling_number"] = event.get("calling_number")
        self.active_calls[call_id]["called_number"] = event.get("called_number")
        self.active_calls[call_id]["called_extension"] = event.get("called_extension")
        
        # Détermination de la direction de l'appel
        if event.get("called_extension") == event.get("calling_number"):
            self.active_calls[call_id]["direction"] = "outgoing"
        else:
            self.active_calls[call_id]["direction"] = "incoming"
        
        # État de connexion
        if "connection_state_desc" in event:
            self.active_calls[call_id]["connection_state"] = event.get("connection_state_desc")
    
    def _process_service_initiated_event(self, call_id: Union[str, int], event: Dict[str, Any]) -> None:
        """Traite un événement d'initiation de service"""
        self.active_calls[call_id]["status"] = "initiated"
        self.active_calls[call_id]["initiated_device"] = event.get("initiated_device")
        
        # Informations complémentaires
        if "connection_call" in event:
            self.active_calls[call_id]["call_id"] = event["connection_call"]
        if "cause_code" in event and event["cause_code"] == 22:  # newCall
            self.active_calls[call_id]["direction"] = "outgoing"
    
    def _process_failed_event(self, call_id: Union[str, int], event: Dict[str, Any], timestamp: str) -> None:
        """Traite un événement d'échec d'appel"""
        self.active_calls[call_id]["status"] = "failed"
        self.active_calls[call_id]["failing_device"] = event.get("failing_device")
        self.active_calls[call_id]["called_device"] = event.get("called_device")
        self.active_calls[call_id]["failure_reason"] = event.get("cause", "unknown")
        self.active_calls[call_id]["failure_code"] = event.get("cause_code")
        self.active_calls[call_id]["end_time"] = timestamp
        
        # Génération d'historique pour les appels échoués
        self._log_call_history(self.active_calls[call_id])
        self._send_call_history_mqtt(self.active_calls[call_id])
    
    def _process_delivered_event(self, call_id: Union[str, int], event: Dict[str, Any]) -> None:
        """Traite un événement de présentation d'appel"""
        self.active_calls[call_id]["status"] = "ringing"
        
        # Mise à jour des informations d'appel
        if "calling_number" in event:
            self.active_calls[call_id]["calling_number"] = event.get("calling_number")
        if "called_number" in event:
            self.active_calls[call_id]["called_number"] = event.get("called_number")
        if "called_extension" in event:
            self.active_calls[call_id]["called_extension"] = event.get("called_extension")
        
        # Direction de l'appel
        if "direction" not in self.active_calls[call_id]:
            self.active_calls[call_id]["direction"] = "incoming"
    
    def _process_established_event(self, call_id: Union[str, int], event: Dict[str, Any], timestamp: str) -> None:
        """Traite un événement de connexion établie"""
        self.active_calls[call_id]["status"] = "connected"
        self.active_calls[call_id]["answer_time"] = timestamp
        
        # État de connexion
        if "connection_state_desc" in event:
            self.active_calls[call_id]["connection_state"] = event.get("connection_state_desc")
    
    def _process_held_event(self, call_id: Union[str, int], event: Dict[str, Any], timestamp: str) -> None:
        """Traite un événement de mise en attente"""
        self.active_calls[call_id]["status"] = "held"
        self.active_calls[call_id]["hold_time"] = timestamp
        self.active_calls[call_id]["holding_device"] = event.get("holding_device")
    
    def _process_retrieved_event(self, call_id: Union[str, int], event: Dict[str, Any], timestamp: str) -> None:
        """Traite un événement de récupération d'appel"""
        self.active_calls[call_id]["status"] = "connected"
        self.active_calls[call_id]["retrieve_time"] = timestamp
        self.active_calls[call_id]["retrieving_device"] = event.get("retrieving_device")
        
        # Calcul du temps d'attente
        if "hold_time" in self.active_calls[call_id]:
            hold_duration = self._calculate_duration(
                self.active_calls[call_id]["hold_time"], 
                timestamp
            )
            self.active_calls[call_id]["last_hold_duration"] = hold_duration
    
    def _process_diverted_event(self, call_id: Union[str, int], event: Dict[str, Any], timestamp: str) -> None:
        """Traite un événement de redirection d'appel"""
        self.active_calls[call_id]["status"] = "diverted"
        self.active_calls[call_id]["divert_time"] = timestamp
        self.active_calls[call_id]["diverted_to"] = event.get("diverted_to_device")
        self.active_calls[call_id]["diversion_type"] = event.get("diversion_type_desc")
    
    def _process_conferenced_event(self, call_id: Union[str, int], event: Dict[str, Any], timestamp: str) -> None:
        """Traite un événement de conférence"""
        self.active_calls[call_id]["status"] = "conferenced"
        self.active_calls[call_id]["conference_time"] = timestamp
        
        # Enregistrer les informations sur la conférence
        if "conf_controller" in event:
            self.active_calls[call_id]["conf_controller"] = event.get("conf_controller")
        if "added_party" in event:
            self.active_calls[call_id]["added_party"] = event.get("added_party")
        
        # Enregistrer les appels impliqués
        if "primary_old_call_id" in event:
            self.active_calls[call_id]["primary_old_call_id"] = event.get("primary_old_call_id")
        if "secondary_old_call_id" in event:
            self.active_calls[call_id]["secondary_old_call_id"] = event.get("secondary_old_call_id")
        
        # Enregistrer la liste des connexions
        if "connections" in event:
            self.active_calls[call_id]["conference_connections"] = event.get("connections")
            
            # Log spécifique pour les informations de conférence
            participants = [conn.get("device") for conn in event.get("connections", [])]
            logger.info(f"Conférence ID {call_id} avec participants: {', '.join(participants)}")
        
        # Créer un événement spécifique pour l'historique
        self._add_conference_to_history(call_id, event)
    
    def _process_transferred_event(self, call_id: Union[str, int], event: Dict[str, Any], timestamp: str) -> None:
        """Traite un événement de transfert"""
        self.active_calls[call_id]["status"] = "transferred"
        self.active_calls[call_id]["transfer_time"] = timestamp
        self.active_calls[call_id]["transferring_device"] = event.get("transferring_device")
        self.active_calls[call_id]["transferred_to"] = event.get("transferred_to_device")
    
    def _process_call_cleared_event(self, call_id: Union[str, int], event: Dict[str, Any], timestamp: str) -> None:
        """Traite un événement de fin d'appel"""
        self.active_calls[call_id]["status"] = "completed"
        self.active_calls[call_id]["end_time"] = timestamp
        self.active_calls[call_id]["duration"] = self._calculate_duration(
            self.active_calls[call_id].get("start_time"), 
            timestamp
        )

        logger.info(f"Fin d'appel ID {call_id} - Génération de l'historique")
        
        # Génération d'historique pour les appels terminés
        self._log_call_history(self.active_calls[call_id])
        self._send_call_history_mqtt(self.active_calls[call_id])

    def _add_conference_to_history(self, call_id: Union[str, int], event: Dict[str, Any]) -> None:
        """
        Ajoute un événement de conférence à l'historique de l'appel
        
        Args:
            call_id: ID de l'appel
            event: Informations sur l'événement
        """
        if call_id not in self.active_calls:
            return
        
        # Extraire les participants pour une meilleure lisibilité
        participants = []
        if "connections" in event:
            participants = [conn.get("device") for conn in event.get("connections", [])]
        
        # Créer l'événement de conférence pour l'historique
        conf_event = {
            "type": "CONFERENCE_DETAILS",
            "timestamp": event.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "controller": event.get("conf_controller", ""),
            "participants": participants,
            "primary_call_id": event.get("primary_old_call_id", 0),
            "secondary_call_id": event.get("secondary_old_call_id", 0)
        }
        
        # Ajouter à l'historique de l'appel
        if "events" in self.active_calls[call_id]:
            self.active_calls[call_id]["events"].append(conf_event)   
    
    def _format_gescall_log(self, event_type: str, event_data: Dict[str, Any]) -> str:
        """
        Génère une ligne de log au format GesCall selon le type d'événement
        """
        call_id = event_data.get("call_id", "")
        xref = event_data.get("cross_ref_identifier", "")
        
        # Format par défaut
        sd_value = "**"
        ges_type = "*Unknown*"
        
        # Formats spécifiques selon l'événement
        if event_type == "EVT_RETRIEVED":
            ges_type = "*EffacerGarde*"
            # sD reste vide pour RETRIEVED
        
        elif event_type == "EVT_CONFERENCED":
            ges_type = "*Conference*"
            # Pour les conférences, sD peut contenir l'added_party
            if "added_party" in event_data:
                sd_value = f"*{event_data['added_party']}*"
            
            # Si des connexions sont disponibles, ajouter le nombre
            if "connections" in event_data:
                return f"GesCall Type={ges_type} NumCall={call_id} Xref={xref} sD={sd_value} Participants={len(event_data['connections'])}"
        
        # Autres types d'événements... [code existant]
        
        return f"GesCall Type={ges_type} NumCall={call_id} Xref={xref} sD={sd_value}"                 
    
    def _log_call_history(self, call: Dict[str, Any]) -> None:
        """
        Affiche l'historique complet d'un appel dans les logs
        
        Args:
            call: Données de l'appel à journaliser
        """
        # Création d'un résumé des événements
        events_summary = []
        for ev in call.get("events", []):
            events_summary.append(f"{ev['timestamp']} - {ev['type']}")

        # Construction du message de log formaté
        summary = (
            f"\n{'=' * 60}\n"
            f"HISTORIQUE D'APPEL - ID: {call.get('call_id', 'inconnu')}\n"
            f"{'=' * 60}\n"
            f"De: {call.get('calling_number', 'inconnu')}"
        )
        
        if call.get('caller_name'):
            summary += f" ({call['caller_name']})"
        
        summary += f"\nVers: {call.get('called_number', 'inconnu')}\n"
        
        if call.get('called_extension'):
            summary += f"Extension interne: {call.get('called_extension')}\n"
        
        # Afficher la direction si disponible
        if call.get('direction'):
            summary += f"Direction: {call.get('direction').upper()}\n"
        
        # Informations temporelles
        summary += (
            f"Début: {call.get('start_time', 'inconnu')}\n"
            f"Fin: {call.get('end_time', 'inconnu')}\n"
            f"Durée: {call.get('duration', 0)} secondes\n"
            f"Statut final: {call.get('status', 'inconnu')}\n"
        )
        
        # Informations sur les transferts
        if any("transfer" in key for key in call.keys()):
            summary += f"\n{'=' * 30} TRANSFERT {'=' * 30}\n"
            for key, value in call.items():
                if "transfer" in key:
                    summary += f"{key}: {value}\n"
        
        # Informations sur les mises en attente
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
        
        # Journalisation dans le log des événements
        event_logger.info(summary)
    
    def _send_call_history_mqtt(self, call: Dict[str, Any]) -> None:
        """
        Envoie l'historique complet de l'appel en JSON sur MQTT
        
        Args:
            call: Données de l'appel à envoyer
        """
        if not self.mqtt_client:
            return
            
        data = {
            "type": "CALL_HISTORY",
            "call_id": call.get("call_id", "unknown"),
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
        
        # Ajout des événements
        for ev in call.get("events", []):
            data["events"].append({
                "timestamp": ev.get("timestamp", ""),
                "type": ev.get("type", "")
            })
        
        # Informations sur les transferts
        if any("transfer" in key for key in call.keys()):
            data["transfer_info"] = {}
            for key, value in call.items():
                if "transfer" in key:
                    data["transfer_info"][key] = value
        
        # Informations sur les mises en attente
        if "hold_time" in call:
            data["hold_info"] = {
                "hold_time": call.get("hold_time"),
                "retrieve_time": call.get("retrieve_time", "unknown"),
                "hold_duration": call.get("last_hold_duration", 0)
            }
        
        # Publication sur MQTT
        mqtt_topic = f"{Config.MQTT_TOPIC}/history"
        payload = json.dumps(data, ensure_ascii=False)
        
        try:
            self.mqtt_client.publish(mqtt_topic, payload)
            logger.info(f"Historique d'appel ID {call.get('call_id')} publié sur MQTT")
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi MQTT: {e}")
    
    # -------------------------------------------------------------------------
    # Méthodes d'analyse et de parsing des événements
    # -------------------------------------------------------------------------
    
    def parse_event(self, data: bytes) -> Dict[str, Any]:
        """
        Analyse un événement CSTA reçu du PABX
        
        Args:
            data: Données brutes reçues
            
        Returns:
            Dict: Informations extraites de l'événement
        """
        hex_data = self.bytes_to_hex(data)
        
        # Initialisation des informations de base
        event_info = {
            "raw_hex": hex_data,
            "parsed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        }
        
        # Détection du type d'événement
        event_type = self._detect_csta_event_type(hex_data)
        event_info["type"] = event_type
        
        # Extraction des informations communes
        common_info = self._extract_common_info(hex_data)
        event_info.update(common_info)
        
        # Extraction des informations sur les appareils
        device_info = self._extract_device_info(hex_data)
        event_info.update(device_info)
        
        # Extraction des informations sur la connexion
        connection_info = self._extract_connection_info(hex_data)
        event_info.update(connection_info)
        
        # Extraction des informations spécifiques selon le type d'événement
        specific_info = self._extract_specific_event_info(event_type, hex_data)
        if specific_info:
            event_info.update(specific_info)
        
        # Sauvegarde de l'exemple complet pour documentation
        self._log_full_hex_message(event_type, hex_data)
        
        return event_info
    
    def _detect_csta_event_type(self, hex_data: str) -> str:
        """
        Détecte le type d'événement CSTA basé sur les codes d'identification
        
        Args:
            hex_data: Données en format hexadécimal
            
        Returns:
            str: Type d'événement détecté
        """
        # Détection prioritaire des keepalives
        if "A2 0A" in hex_data and ("02 01 34" in hex_data or "02 01 01 30 05 02 01 34" in hex_data):
            return "KEEPALIVE"
        
        # Dictionnaire des codes d'événements
        event_codes = {
            "02 01 15": "NEW_CALL",        # Peut être SERVICE_INITIATED ou FAILED
            "02 01 01": "CALL_CLEARED",    # Appel terminé
            "02 01 03": "DELIVERED",       # Appel présenté
            "02 01 04": "ESTABLISHED",     # Connexion établie
            "02 01 06": "HELD",            # Mise en attente
            "02 01 0B": "RETRIEVED",       # Récupération
            "02 01 0C": "CONFERENCED",     # Conférence
            "02 01 0E": "DIVERTED",        # Redirection
            "02 01 0F": "TRANSFERRED"      # Transfert
        }
        
        # Recherche du code dans les données
        for code, event_type in event_codes.items():
            if code in hex_data:
                # Vérifications spécifiques pour éviter les faux positifs
                
                # Pour SERVICE_INITIATED et FAILED (partagent le code 02 01 15)
                if code == "02 01 15":
                    if "4E 01 06" in hex_data and "0A 01 0D" in hex_data:
                        return "EVT_FAILED"
                    elif "55 04 01" in hex_data and "A5" in hex_data:
                        return "NEW_CALL"
                    else:
                        return "EVT_SERVICE_INITIATED"
                
                # Pour CALL_CLEARED et DELIVERED, vérifier que ce n'est pas un keepalive
                elif (code in ["02 01 01", "02 01 03"] and 
                      "A2 0A" in hex_data and "02 01 34" in hex_data):
                    continue  # C'est un keepalive
                
                return event_type
        
        # Vérification des formats anciens
        legacy_event_types = {
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
        
        for hex_code, event_type in legacy_event_types.items():
            if hex_code in hex_data:
                return event_type
        
        # Si aucun type connu n'est trouvé
        return "UNKNOWN"
    
    def _extract_common_info(self, hex_data: str) -> Dict[str, Any]:
        """
        Extrait les informations communes à la plupart des événements CSTA
        
        Args:
            hex_data: Données en format hexadécimal
            
        Returns:
            Dict: Informations communes extraites
        """
        info = {}
        
        # Extraction de l'identifiant d'invocation
        try:
            invoke_idx = hex_data.find("02 02")
            if invoke_idx != -1:
                invoke_hex = hex_data[invoke_idx+6:invoke_idx+14].replace(" ", "")
                info["invoke_id"] = int(invoke_hex, 16)
        except Exception as e:
            logger.debug(f"Erreur extraction invoke_id: {e}")
        
        # Extraction de l'identifiant d'appel
        try:
            call_id_idx = hex_data.find("82 02")
            if call_id_idx != -1:
                call_id_hex = hex_data[call_id_idx+6:call_id_idx+14].replace(" ", "")
                info["call_id"] = int(call_id_hex, 16)
        except Exception as e:
            logger.debug(f"Erreur extraction call_id: {e}")
        
        # Extraction de l'horodatage
        try:
            time_idx = hex_data.find("17 0D")
            if time_idx != -1:
                time_str = ""
                for i in range(0, 39, 3):
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
            logger.debug(f"Erreur extraction timestamp: {e}")
        
        return info
    
    def _extract_device_info(self, hex_data: str) -> Dict[str, Any]:
        """
        Extrait les informations sur les appareils impliqués
        
        Args:
            hex_data: Données en format hexadécimal
            
        Returns:
            Dict: Informations sur les appareils
        """
        devices = {}
        
        # Extraction du numéro appelant (format 63 07 84 05 + ASCII)
        try:
            calling_idx = hex_data.find("63 07 84 05")
            if calling_idx != -1:
                calling_num = self._extract_ascii_number(hex_data, calling_idx + 12)
                if calling_num:
                    devices["calling_number"] = calling_num
        except Exception as e:
            logger.debug(f"Erreur extraction calling_number: {e}")
        
        # Extraction du numéro appelé (format 82 0B + ASCII)
        try:
            called_idx = hex_data.find("82 0B")
            if called_idx != -1:
                length_hex = int("0B", 16)  # 11 caractères max
                
                called_number = ""
                for i in range(0, length_hex * 3, 3):
                    pos = called_idx + 6 + i
                    if pos + 2 <= len(hex_data):
                        byte_hex = hex_data[pos:pos+2]
                        try:
                            byte_val = int(byte_hex, 16)
                            if (48 <= byte_val <= 57) or byte_val in [43, 42, 35, 32]:
                                called_number += chr(byte_val)
                            else:
                                break
                        except ValueError:
                            break
                
                # Normalisation du numéro
                called_number = ''.join(c for c in called_number if c.isdigit() or c in ['+', '*', '#'])
                
                if called_number.startswith("00"):
                    called_number = "0" + called_number[2:]
                
                if called_number:
                    devices["called_number"] = called_number
        except Exception as e:
            logger.debug(f"Erreur extraction called_number: {e}")
        
        # Extraction de l'extension appelée (format 62 07 84 05 + ASCII)
        try:
            extension_idx = hex_data.find("62 07 84 05")
            if extension_idx != -1:
                extension = self._extract_ascii_number(hex_data, extension_idx + 12)
                if extension:
                    devices["called_extension"] = extension
        except Exception as e:
            logger.debug(f"Erreur extraction called_extension: {e}")
        
        # Extraction du périphérique initiateur (format alternatif)
        try:
            initiator_idx = hex_data.find("55 04 01")
            if initiator_idx != -1:
                initiator = self._extract_ascii_number(hex_data, initiator_idx + 9)
                if initiator:
                    devices["initiator_device"] = initiator
        except Exception as e:
            logger.debug(f"Erreur extraction initiator_device: {e}")
        
        return devices
    
    def _extract_connection_info(self, hex_data: str) -> Dict[str, Any]:
        """
        Extrait les informations sur l'état de la connexion
        
        Args:
            hex_data: Données en format hexadécimal
            
        Returns:
            Dict: Informations sur la connexion
        """
        connection = {}
        
        # Extraction de l'état de connexion (format 64 02 88 XX ou 4E 01 XX)
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
                connection["connection_state_desc"] = Config.CONNECTION_STATES.get(
                    conn_state, f"unknown({conn_state})"
                )
        except Exception as e:
            logger.debug(f"Erreur extraction connection_state: {e}")
        
        # Extraction de la cause (format 0A 01 XX)
        try:
            cause_idx = hex_data.find("0A 01")
            if cause_idx != -1:
                cause_code = int(hex_data[cause_idx+6:cause_idx+8], 16)
                connection["cause_code"] = cause_code
                connection["cause"] = Config.CAUSE_CODES.get(
                    cause_code, f"unknown({cause_code})"
                )
        except Exception as e:
            logger.debug(f"Erreur extraction cause: {e}")
        
        # Extraction du cross reference identifier
        try:
            xref_idx = hex_data.find("83 04")
            if xref_idx != -1:
                xref_hex = hex_data[xref_idx+6:xref_idx+18].replace(" ", "")
                connection["cross_ref_identifier"] = int(xref_hex, 16)
        except Exception as e:
            logger.debug(f"Erreur extraction cross_ref_identifier: {e}")
        
        return connection
    
    def _extract_specific_event_info(self, event_type: str, hex_data: str) -> Dict[str, Any]:
        """
        Extrait les informations spécifiques selon le type d'événement
        
        Args:
            event_type: Type d'événement CSTA
            hex_data: Données en format hexadécimal
            
        Returns:
            Dict: Informations spécifiques au type d'événement
        """
        # Dispatch vers la méthode d'extraction appropriée
        if event_type == "HELD":
            return self._extract_held_info(hex_data)
        elif event_type == "RETRIEVED":
            return self._extract_retrieved_info(hex_data)
        elif event_type == "CONFERENCED":
            return self._extract_conferenced_info(hex_data)
        elif event_type == "DIVERTED":
            return self._extract_diverted_info(hex_data)
        elif event_type == "TRANSFERRED":
            return self._extract_transferred_info(hex_data)
        elif event_type == "EVT_FAILED":
            return self._extract_failed_info(hex_data)
        elif event_type == "EVT_SERVICE_INITIATED":
            return self._extract_service_initiated_info(hex_data)
        
        # Aucune information spécifique pour ce type d'événement
        return {}
    
    def _extract_held_info(self, hex_data: str) -> Dict[str, Any]:
        """
        Extrait les informations spécifiques à l'événement HELD
        
        Args:
            hex_data: Données en format hexadécimal
            
        Returns:
            Dict: Informations spécifiques
        """
        info = {}
        
        # Déterminer qui a mis l'appel en attente
        try:
            holding_device_idx = hex_data.find("63 07 84 05")
            if holding_device_idx != -1:
                holding_device = self._extract_ascii_number(hex_data, holding_device_idx + 12)
                if holding_device:
                    info["holding_device"] = holding_device
        except Exception as e:
            logger.debug(f"Erreur extraction holding_device: {e}")
        
        return info
    def _extract_retrieved_info(self, hex_data: str) -> Dict[str, Any]:
        """
        Extrait les informations spécifiques à l'événement RETRIEVED
        
        Args:
            hex_data: Données en format hexadécimal
            
        Returns:
            Dict: Informations spécifiques
        """
        info = {}
        
        # Dispositif qui récupère l'appel
        try:
            retrieving_device_idx = hex_data.find("63 07 84 05")
            if retrieving_device_idx != -1:
                retrieving_device = self._extract_ascii_number(hex_data, retrieving_device_idx + 12)
                if retrieving_device:
                    info["retrieving_device"] = retrieving_device
        except Exception as e:
            logger.debug(f"Erreur extraction retrieving_device: {e}")
        
        # Vérifier l'état de connexion
        try:
            conn_state_idx = hex_data.find("4E 01")
            if conn_state_idx != -1:
                conn_state = int(hex_data[conn_state_idx+6:conn_state_idx+8], 16)
                info["connection_state"] = conn_state
                info["connection_state_desc"] = Config.CONNECTION_STATES.get(
                    conn_state, f"unknown({conn_state})"
                )
        except Exception as e:
            logger.debug(f"Erreur extraction connection_state: {e}")
        
        return info    

    def _extract_conferenced_info(self, hex_data: str) -> Dict[str, Any]:
        """
        Extrait les informations spécifiques à l'événement CONFERENCED
        
        Args:
            hex_data: Données en format hexadécimal
            
        Returns:
            Dict: Informations spécifiques
        """
        info = {}
        
        # Récupérer les informations sur les appels impliqués
        try:
            # Premier appel impliqué (PrimaryOldCall)
            primary_call_idx = hex_data.find("6B 0A 82 02")
            if primary_call_idx != -1:
                primary_call_hex = hex_data[primary_call_idx+6:primary_call_idx+14].replace(" ", "")
                info["primary_old_call_id"] = int(primary_call_hex, 16)
            
            # Deuxième appel impliqué (SecondaryOldCall)
            secondary_call_idx = hex_data.find("6B 0A 82 02", primary_call_idx + 20)
            if secondary_call_idx != -1:
                secondary_call_hex = hex_data[secondary_call_idx+6:secondary_call_idx+14].replace(" ", "")
                info["secondary_old_call_id"] = int(secondary_call_hex, 16)
            
            # Contrôleur de conférence
            conf_controller_idx = hex_data.find("63 07 84 05")
            if conf_controller_idx != -1:
                conf_controller = self._extract_ascii_number(hex_data, conf_controller_idx + 12)
                if conf_controller:
                    info["conf_controller"] = conf_controller
            
            # Participant ajouté
            added_party_idx = hex_data.find("63 06 82 04")
            if added_party_idx != -1:
                added_party = self._extract_ascii_number(hex_data, added_party_idx + 12)
                if added_party:
                    info["added_party"] = added_party
        
        except Exception as e:
            logger.debug(f"Erreur extraction conférence de base: {e}")
        
        # Extraire la liste des connexions (partie plus complexe)
        try:
            # Trouver les marqueurs de la liste des connexions
            connection_entries = []
            
            # Rechercher le pattern "80=XX 81= 82=YY 83=ZZ" répété
            device_markers = [m.start() for m in re.finditer("80", hex_data)]
            
            for marker in device_markers:
                # Vérifier si c'est un marqueur de début de connexion
                if marker > 0 and hex_data[marker-3:marker] in ["13 ", "12 ", "19 "]:
                    try:
                        # Extraire le numéro de poste/device
                        device = self._extract_ascii_string(hex_data, marker + 3, 15)
                        
                        # Chercher l'ID d'appel associé
                        call_id_idx = hex_data.find("82 02", marker, marker + 50)
                        call_id = 0
                        if call_id_idx != -1:
                            call_id_hex = hex_data[call_id_idx+6:call_id_idx+14].replace(" ", "")
                            call_id = int(call_id_hex, 16)
                        
                        # Chercher l'équipement
                        equipment_idx = hex_data.find("83 04", marker, marker + 50)
                        equipment = ""
                        if equipment_idx != -1:
                            equipment = hex_data[equipment_idx+6:equipment_idx+18].replace(" ", "")
                        
                        connection_entries.append({
                            "device": device,
                            "call_id": call_id,
                            "equipment": equipment
                        })
                    except Exception as e:
                        logger.debug(f"Erreur traitement entrée connexion: {e}")
            
            if connection_entries:
                info["connections"] = connection_entries
        except Exception as e:
            logger.debug(f"Erreur extraction liste de connexions: {e}")
        
        return info

    def _extract_diverted_info(self, hex_data: str) -> Dict[str, Any]:
        """
        Extrait les informations spécifiques à l'événement DIVERTED
        
        Args:
            hex_data: Données en format hexadécimal
            
        Returns:
            Dict: Informations spécifiques
        """
        info = {}
        
        # Extraire la destination de la redirection
        try:
            divert_to_idx = hex_data.find("66 07 84 05")
            if divert_to_idx != -1:
                divert_to = self._extract_ascii_number(hex_data, divert_to_idx + 12)
                if divert_to:
                    info["diverted_to_device"] = divert_to
        except Exception as e:
            logger.debug(f"Erreur extraction diverted_to_device: {e}")
        
        # Extraire le type de redirection
        try:
            divert_type_idx = hex_data.find("67 01")
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
            logger.debug(f"Erreur extraction diversion_type: {e}")
        
        return info
    
    def _extract_transferred_info(self, hex_data: str) -> Dict[str, Any]:
        """
        Extrait les informations spécifiques à l'événement TRANSFERRED
        
        Args:
            hex_data: Données en format hexadécimal
            
        Returns:
            Dict: Informations spécifiques
        """
        info = {}
        
        # Extraire l'appareil qui a effectué le transfert
        try:
            transferring_device_idx = hex_data.find("63 07 84 05")
            if transferring_device_idx != -1:
                transferring_device = self._extract_ascii_number(hex_data, transferring_device_idx + 12)
                if transferring_device:
                    info["transferring_device"] = transferring_device
        except Exception as e:
            logger.debug(f"Erreur extraction transferring_device: {e}")
        
        # Extraire l'appareil vers lequel l'appel a été transféré
        try:
            transferred_to_idx = hex_data.find("68 07 84 05")
            if transferred_to_idx != -1:
                transferred_to = self._extract_ascii_number(hex_data, transferred_to_idx + 12)
                if transferred_to:
                    info["transferred_to_device"] = transferred_to
        except Exception as e:
            logger.debug(f"Erreur extraction transferred_to_device: {e}")
        
        return info
    
    def _extract_service_initiated_info(self, hex_data: str) -> Dict[str, Any]:
        """
        Extrait les informations spécifiques à l'événement SERVICE_INITIATED
        
        Args:
            hex_data: Données en format hexadécimal
            
        Returns:
            Dict: Informations spécifiques
        """
        info = {}
        
        # Extraction du ConnectionCall
        try:
            call_id_idx = hex_data.find("82 02")
            if call_id_idx != -1:
                call_id_hex = hex_data[call_id_idx+6:call_id_idx+11].replace(" ", "")
                info["call_id"] = int(call_id_hex, 16)
        except Exception as e:
            logger.debug(f"Erreur extraction call_id: {e}")
        
        # Extraction du CrossRefIdentifier
        try:
            xref_idx = hex_data.find("02 02")
            if xref_idx != -1:
                xref_hex = hex_data[xref_idx+6:xref_idx+11].replace(" ", "")
                info["cross_ref_identifier"] = int(xref_hex, 16)
        except Exception as e:
            logger.debug(f"Erreur extraction cross_ref: {e}")
        
        # Extraction du périphérique initiateur
        try:
            init_dev_idx = hex_data.find("55 04 01")
            if init_dev_idx != -1:
                init_dev = self._extract_ascii_number(hex_data, init_dev_idx + 9)
                if init_dev:
                    info["initiated_device"] = init_dev
        except Exception as e:
            logger.debug(f"Erreur extraction initiated_device: {e}")
        
        return info
    
    def _extract_failed_info(self, hex_data: str) -> Dict[str, Any]:
        """
        Extrait les informations spécifiques à l'événement FAILED
        
        Args:
            hex_data: Données en format hexadécimal
            
        Returns:
            Dict: Informations spécifiques
        """
        info = {}
        
        # Extraction du ConnectionCall
        try:
            call_id_idx = hex_data.find("82 02")
            if call_id_idx != -1:
                call_id_hex = hex_data[call_id_idx+6:call_id_idx+11].replace(" ", "")
                info["call_id"] = int(call_id_hex, 16)
        except Exception as e:
            logger.debug(f"Erreur extraction call_id: {e}")
        
        # Extraction du FailingDevice
        try:
            failing_dev_idx = hex_data.find("63 07 84 05")
            if failing_dev_idx != -1:
                failing_device = self._extract_ascii_number(hex_data, failing_dev_idx + 12)
                if failing_device:
                    info["failing_device"] = failing_device
        except Exception as e:
            logger.debug(f"Erreur extraction failing_device: {e}")
        
        # Extraction du CalledDevice
        try:
            called_dev_idx = hex_data.find("62 05 80 03")
            if called_dev_idx != -1:
                called_device = self._extract_ascii_string(hex_data, called_dev_idx + 12)
                if called_device:
                    info["called_device"] = called_device
        except Exception as e:
            logger.debug(f"Erreur extraction called_device: {e}")
        
        return info
    
    def _handle_keepalive(self, data: bytes) -> Tuple[Dict[str, Any], Optional[bytes]]:
        """
        Traite un message keepalive et génère la réponse appropriée
        
        Args:
            data: Données brutes du keepalive
            
        Returns:
            Tuple: Informations sur le keepalive et réponse éventuelle
        """
        hex_data = self.bytes_to_hex(data)
        keepalive_info = {
            "type": "KEEPALIVE",
            "raw_hex": hex_data,
            "parsed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        }
        
        # Extraction de l'identifiant d'invocation
        try:
            invoke_id_pattern = r"02 01 34 05 ([0-9A-F]{2})"
            id_match = re.search(invoke_id_pattern, hex_data)
            if id_match:
                keepalive_id = id_match.group(1)
                keepalive_info["id"] = keepalive_id
                
                # Génération de la réponse
                response = self.hex_to_bytes(
                    f"00 0D A2 0B 02 02 00 00 30 05 02 01 34 05 {keepalive_id}"
                )
                keepalive_info["response"] = response
                return keepalive_info, response
        except Exception as e:
            logger.error(f"Erreur lors du traitement du keepalive: {e}")
        
        # Si aucune réponse n'est générée
        return keepalive_info, None
    
    def _enrich_call_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrichit un événement d'appel avec des informations complémentaires
        
        Args:
            event: Événement à enrichir
            
        Returns:
            Dict: Événement enrichi
        """
        # Copie pour éviter de modifier l'original
        enriched_event = event.copy()
        
        # Ajouter des informations de transfert si pertinent
        if "call_id" in event:
            transfer_info = self._detect_transfer_sequence(event["call_id"])
            if transfer_info:
                enriched_event["transfer_detected"] = True
                enriched_event["transfer_type"] = transfer_info["transfer_type"]
                enriched_event["related_calls"] = transfer_info["related_calls"]
                
                # Pour les NEW_CALL avec transfert potentiel
                if event["type"] == "NEW_CALL" and transfer_info["related_calls"]:
                    previous_call_id = transfer_info["related_calls"][0]
                    if previous_call_id in self.active_calls:
                        previous_call = self.active_calls[previous_call_id]
                        
                        # Informations contextuelles
                        if "calling_number" in previous_call and "called_number" in previous_call:
                            enriched_event["original_caller"] = previous_call.get("calling_number")
                            enriched_event["original_called"] = previous_call.get("called_number")
                            
                            # Détection de transfert en cours
                            if (enriched_event.get("calling_number") == previous_call.get("called_number") and
                                "called_number" in enriched_event and 
                                enriched_event["called_number"] != previous_call["calling_number"]):
                                enriched_event["transfer_in_progress"] = True
                                
                            # Détection de transfert terminé
                            if (enriched_event.get("calling_number") == previous_call.get("calling_number") and
                                "called_number" in enriched_event and
                                enriched_event["called_number"] != previous_call["called_number"]):
                                enriched_event["transfer_completed"] = True
        
        return enriched_event
    
    def _detect_transfer_sequence(self, call_id: Union[str, int]) -> Optional[Dict[str, Any]]:
        """
        Détecte si un appel fait partie d'une séquence de transfert
        
        Args:
            call_id: Identifiant de l'appel
            
        Returns:
            Optional[Dict]: Informations sur le transfert si détecté
        """
        # Si l'appel n'existe pas
        if call_id not in self.active_calls:
            return None
        
        # Récupérer les informations sur l'appel actuel
        current_call = self.active_calls[call_id]
        
        # Initialisation des informations de transfert
        transfer_info = {
            "is_transfer": False,
            "transfer_type": None,
            "related_calls": [],
        }
        
        # Parcourir tous les appels actifs pour trouver des relations
        for related_id, related_call in self.active_calls.items():
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
                        # Vérifier les modèles de transfert
                        
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
                                transfer_info["transfer_type"] = "external"  # Transfert externe
                                transfer_info["related_calls"].append(related_id)
                        
                        # Cas 3: Appelé commun mais sources différentes (conférence)
                        elif current_call.get("called_number") == related_call.get("called_number"):
                            transfer_info["is_transfer"] = True
                            transfer_info["transfer_type"] = "conference_candidate"
                            transfer_info["related_calls"].append(related_id)
                except Exception as e:
                    logger.debug(f"Erreur analyse des relations d'appel: {e}")
        
        # Si aucun transfert n'est détecté
        if not transfer_info["is_transfer"]:
            return None
        
        return transfer_info
    
    # -------------------------------------------------------------------------
    # Méthodes utilitaires pour les formats de données et le logging
    # -------------------------------------------------------------------------
    
    def _calculate_duration(self, start_time: str, end_time: str) -> int:
        """
        Calcule la durée entre deux horodatages en secondes
        
        Args:
            start_time: Horodatage de début
            end_time: Horodatage de fin
            
        Returns:
            int: Durée en secondes
        """
        try:
            start = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            end = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            return int((end - start).total_seconds())
        except Exception:
            return 0
    
    def _extract_ascii_number(self, hex_data: str, start_idx: int, length: int = 10) -> str:
        """
        Extrait un numéro au format ASCII depuis des données hexadécimales
        
        Args:
            hex_data: Données hexadécimales
            start_idx: Position de départ
            length: Longueur maximale à extraire
            
        Returns:
            str: Numéro extrait
        """
        number = ""
        for i in range(0, length * 3, 3):
            if start_idx + i >= len(hex_data):
                break
            byte_hex = hex_data[start_idx + i:start_idx + i + 2]
            if byte_hex in ["30","31","32","33","34","35","36","37","38","39"]:
                number += chr(int(byte_hex, 16))
            else:
                if len(number) > 0:
                    break
        return number
    
    def _extract_ascii_string(self, hex_data: str, start_idx: int, length: int = 20) -> str:
        """
        Extrait une chaîne ASCII depuis des données hexadécimales
        
        Args:
            hex_data: Données hexadécimales
            start_idx: Position de départ
            length: Longueur maximale à extraire
            
        Returns:
            str: Chaîne extraite
        """
        try:
            result = ""
            for i in range(0, length*3, 3):
                if start_idx + i >= len(hex_data):
                    break
                byte_hex = hex_data[start_idx + i:start_idx + i + 2]
                try:
                    byte_val = int(byte_hex, 16)
                    if 32 <= byte_val <= 126:  # Caractères ASCII imprimables
                        result += chr(byte_val)
                    else:
                        if i > 0:  # Arrêt au premier caractère non imprimable après un début de chaîne
                            break
                except ValueError:
                    break
            return result
        except Exception as e:
            logger.debug(f"Erreur extraction ASCII: {e}")
            return ""
        