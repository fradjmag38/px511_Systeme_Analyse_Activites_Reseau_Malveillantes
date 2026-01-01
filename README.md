# RT-IDS – Système de Détection d’Intrusions en Temps Réel

## Présentation du projet
Ce projet implémente un **système de détection d’intrusions réseau en temps réel (RT-IDS)** intégrant des techniques d’analyse de trafic réseau et de Machine Learning.  
L’objectif est de détecter à la fois :
- des **attaques connues** à l’aide d’un modèle supervisé (Random Forest),
- des **comportements anormaux ou inconnus (zero-day)** via un modèle non supervisé (Autoencodeur).

Le système inclut une **application web** permettant la visualisation en temps réel des flux analysés et des alertes générées.

---

## Architecture générale
Le système repose sur les composants suivants :
- Capture et simulation de trafic réseau,
- Extraction et construction de flux réseau,
- Prétraitement des caractéristiques,
- Inférence en temps réel via des modèles entraînés,
- Interface web pour la visualisation et l’analyse.

Les modèles ont été entraînés principalement à partir du dataset **CICIDS2018**.

---

## Arborescence du projet

```text
RT-IDS/
│   app.py                     # Application web Flask (serveur principal)
│   demo_traffic.py            # Génération / simulation de trafic réseau
│   input_logs.csv             # Fichier d'entrée (logs simulés)
│   output_logs.csv            # Fichier de sortie (résultats d'inférence)
│   README.md                  # Documentation du projet
│   requirements.txt           # Dépendances Python
│
├── flow/                      # Construction des flux réseau
│   ├── Flow.py
│   ├── FlowFeature.py
│   ├── PacketInfo.py
│   └── __pycache__/
│
├── models/                    # Modèles et pipelines sauvegardés
│   ├── autoencoder_39ft.hdf5
│   ├── model.pkl              # Random Forest entraîné
│   ├── preprocess_pipeline_AE_39ft.save
│   └── scaler.pkl
│
├── static/                    # Ressources statiques pour l'interface web
│   ├── css/
│   ├── images/
│   └── js/
│
├── templates/                 # Templates HTML
│   └── index.html
│
└── training/
    └── models_training.ipynb  # Notebook d'entraînement des modèles

```
---
## Requirements
1. Windows OS.

2. Python 3.9:
    *  64-bit: https://www.python.org/ftp/python/3.9.13/python-3.9.13-amd64.exe 
    *  32-bit: https://www.python.org/ftp/python/3.9.13/python-3.9.13.exe


3. Npcap 1.71:
    https://npcap.com/dist/npcap-1.71.exe

## environnement:
    python3.9 -m venv venv
    source venv/bin/activate
    python -m pip install -r requirements.txt
---
executer le programme:

<code>python app.py</code>
---
## Auteurs:

Projet réalisé dans le cadre du module PX511 – Grenoble INP ESISAR

Fradj Dorbez

Hamza Ouni

Ange Akhenaton Degnan Kouassi

Encadrante : Mme Om-Essaad Slama
---