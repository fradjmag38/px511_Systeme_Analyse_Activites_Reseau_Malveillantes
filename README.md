# RT-IDS – Système de Détection d’Intrusions en Temps Réel

# SIEM sans IA avec Suricata & ELK Stack sur Docker

---

## Présentation du projet

Cette partie du projet consiste à mettre en place une infrastructure de supervision de sécurité basée sur **Suricata** (IDS) et **Filebeat** (agent de collecte), avec une logique de pipeline JSON pour enrichir les logs. Le tout fonctionne dans un environnement entièrement **Dockerisé**.

---

## Arborescence du projet

```text
SIEM_Suricata/
├── pipeline/                  # Pipelines Elasticsearch (prétraitement des logs)
│   └── add_timestamp.json     # Ajout / normalisation des timestamps
│
├── suricata/                  # Configuration et sorties de Suricata
│   ├── logs/                  # Journaux générés par l’analyse PCAP
│   │   ├── eve.json           # Logs JSON structurés (alertes, flows, stats)
│   │   ├── fast.log           # Alertes Suricata en format texte
│   │   ├── stats.log          # Statistiques de Suricata
│   │   └── suricata.log       # Logs internes du moteur Suricata
│   │
│   └── rules/                 # Règles de détection
│       └── custom.rules       # Règles Suricata personnalisées
│
│   └── suricata.yaml          # Fichier de configuration principal de Suricata
│
├── docker-compose.yml         # Déploiement ELK + Suricata + Filebeat
├── Dockerfile.filebeat        # Image Filebeat personnalisée
├── filebeat.yml               # Configuration de collecte des logs Suricata

```

---


## Lancer le SIEM

```bash
docker-compose up -d
```
Dans le navigateur ```http://127.0.0.1:5601/``` pour accederà l'interface Kibana
Vérifiez dans `suricata.yaml` que l’interface réseau est bien définie (`enp0s3` dans notre cas).

---

## Résultat attendu

- Logs de sécurité détectés en temps réel
- Pipeline JSON opérationnel
- Envoi des événements vers la sortie souhaitée

---


## Documentation

- [Documentation Suricata](https://suricata.readthedocs.io/)
- [Documentation ELK Stack](https://www.elastic.co/docs)
- [Documentation Docker](https://docs.docker.com/manuals/)

---

## Auteurs:

Projet réalisé dans le cadre du module PX511 – Grenoble INP ESISAR

Fradj Dorbez

Hamza Ouni

Ange Akhenaton Degnan Kouassi

Encadrante : Mme Om-Essaad Slama
---
