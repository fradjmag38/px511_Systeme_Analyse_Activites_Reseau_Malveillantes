# ==============================================================
# 1. Imports – Réseau, Web, Concurrence
# ==============================================================
from flask_socketio import SocketIO, emit
from flask import Flask, render_template, url_for, copy_current_request_context, request
from threading import Thread, Event
from time import sleep
from random import random

from scapy.sendrecv import sniff

# ==============================================================
# 2. Imports – Logique IDS / Flows
# ==============================================================
from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

# ==============================================================
# 3. Imports – Data / ML / Utils
# ==============================================================
import numpy as np
import pandas as pd
import pickle
import joblib
import dill
import csv
import json
import traceback
import warnings
warnings.filterwarnings("ignore")

from scipy.stats import norm
from tensorflow import keras
from lime import lime_tabular
import plotly
import plotly.graph_objs

import ipaddress
from urllib.request import urlopen

__author__ = 'hoang'

# ==============================================================
# 4. Fonctions utilitaires (IP Geo)
# ==============================================================
def ipInfo(addr=''):
    """Retourne le pays d'une IP via ipinfo.io"""
    try:
        url = 'https://ipinfo.io/json' if addr == '' else f'https://ipinfo.io/{addr}/json'
        res = urlopen(url)
        data = json.load(res)
        return data.get('country')
    except Exception:
        return None

# ==============================================================
# 5. Initialisation Flask + SocketIO
# ==============================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['DEBUG'] = True

socketio = SocketIO(app, async_mode=None, logger=True, engineio_logger=True)

# ==============================================================
# 6. Thread de capture réseau
# ==============================================================
thread = Thread()
thread_stop_event = Event()

# ==============================================================
# 7. Fichiers de logs
# ==============================================================
f = open("output_logs.csv", 'w')
w = csv.writer(f)
f2 = open("input_logs.csv", 'w')
w2 = csv.writer(f2)

# ==============================================================
# 8. Colonnes & Features
# ==============================================================
cols = ['FlowID','FlowDuration','BwdPacketLenMax','BwdPacketLenMin','BwdPacketLenMean','BwdPacketLenStd',
        'FlowIATMean','FlowIATStd','FlowIATMax','FlowIATMin','FwdIATTotal','FwdIATMean','FwdIATStd',
        'FwdIATMax','FwdIATMin','BwdIATTotal','BwdIATMean','BwdIATStd','BwdIATMax','BwdIATMin',
        'FwdPSHFlags','FwdPackets_s','MaxPacketLen','PacketLenMean','PacketLenStd','PacketLenVar',
        'FINFlagCount','SYNFlagCount','PSHFlagCount','ACKFlagCount','URGFlagCount','AvgPacketSize',
        'AvgBwdSegmentSize','InitWinBytesFwd','InitWinBytesBwd','ActiveMin','IdleMean','IdleStd',
        'IdleMax','IdleMin','Src','SrcPort','Dest','DestPort','Protocol','FlowStartTime',
        'FlowLastSeen','PName','PID','Classification','Probability','Risk']

# Features utilisées par l'AutoEncoder
ae_features = np.array(cols[1:40])

# ==============================================================
# 9. Variables globales IDS
# ==============================================================
flow_count = 0
flow_df = pd.DataFrame(columns=cols)
src_ip_dict = {}
current_flows = {}
FlowTimeout = 600

# ==============================================================
# 10. Chargement des modèles ML
# ==============================================================
ae_scaler = joblib.load("models/preprocess_pipeline_AE_39ft.save")
ae_model = keras.models.load_model('models/autoencoder_39ft.hdf5')

with open('models/model.pkl', 'rb') as f:
    classifier = pickle.load(f)

predict_fn_rf = lambda x: classifier.predict_proba(x).astype(float)


# ==============================================================
# 12. Classification d'un Flow
# ==============================================================
def classify(features):
    global flow_count

    feature_string = [str(i) for i in features[39:]]
    record = features.copy()
    features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features[:39]]

    # Comptage IP source
    src_ip_dict[feature_string[0]] = src_ip_dict.get(feature_string[0], 0) + 1

    # Ajout géolocalisation
    for i in [0, 2]:
        ip = feature_string[i]
        if not ipaddress.ip_address(ip).is_private:
            country = ipInfo(ip)
            img = f'<img class="flag flag-{country.lower()}" />' if country else '<img class="flag flag-unknown" />'
        else:
            img = '<img class="flag flag-lan" />'
        feature_string[i] += img

    if np.nan in features:
        return

    # Prédiction
    result = classifier.predict([features])
    proba = predict_fn_rf([features])
    proba_score = [proba[0].max()]
    proba_risk = sum(proba[0][1:])

    if proba_risk > 0.8: risk = ["Very High"]
    elif proba_risk > 0.6: risk = ["High"]
    elif proba_risk > 0.4: risk = ["Medium"]
    elif proba_risk > 0.2: risk = ["Low"]
    else: risk = ["Minimal"]

    classification = [str(result[0])]

    flow_count += 1
    flow_df.loc[len(flow_df)] = [flow_count] + record + classification + proba_score + risk

    ip_data = pd.DataFrame({'SourceIP': src_ip_dict.keys(), 'count': src_ip_dict.values()}).to_json(orient='records')

    socketio.emit('newresult', {
        'result': [flow_count] + feature_string + classification + proba_score + risk,
        'ips': json.loads(ip_data)
    }, namespace='/test')

    return [flow_count] + record + classification + proba_score + risk

# ==============================================================
# 13. Traitement d'un paquet réseau (Scapy)
# ==============================================================
def newPacket(p):
    try:
        packet = PacketInfo()
        packet.setDest(p); packet.setSrc(p)
        packet.setSrcPort(p); packet.setDestPort(p)
        packet.setProtocol(p); packet.setTimestamp(p)
        packet.setPSHFlag(p); packet.setFINFlag(p)
        packet.setSYNFlag(p); packet.setACKFlag(p)
        packet.setURGFlag(p); packet.setRSTFlag(p)
        packet.setPayloadBytes(p); packet.setHeaderBytes(p)
        packet.setPacketSize(p); packet.setWinBytes(p)
        packet.setFwdID(); packet.setBwdID()

        # Gestion flows
        if packet.getFwdID() in current_flows:
            flow = current_flows[packet.getFwdID()]
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                current_flows[packet.getFwdID()] = Flow(packet)
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
            else:
                flow.new(packet, 'fwd')

        elif packet.getBwdID() in current_flows:
            flow = current_flows[packet.getBwdID()]
            flow.new(packet, 'bwd')
        else:
            current_flows[packet.getFwdID()] = Flow(packet)

    except AttributeError:
        return
    except Exception:
        traceback.print_exc()

# ==============================================================
# 14. Thread principal de sniffing
# ==============================================================
def snif_and_detect():
    while not thread_stop_event.isSet():
        sniff(prn=newPacket)
        for f in current_flows.values():
            classify(f.terminated())

# ==============================================================
# 15. Routes Flask
# ==============================================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/flow-detail')
def flow_detail():
    flow_id = request.args.get('flow_id', -1, int)
    flow = flow_df.loc[flow_df['FlowID'] == flow_id]
    X = [flow.values[0,1:40]]

    #exp = explainer.explain_instance(X[0], predict_fn_rf, num_features=6, top_labels=1) if explainer else None

    X_transformed = ae_scaler.transform(X)
    reconstruct = ae_model.predict(X_transformed)
    err = reconstruct - X_transformed
    abs_err = np.abs(err)

    idx = np.argpartition(abs_err, -5)[-5:]
    cols_err = ae_features[idx]
    err_vals = err[0][idx]

    plot_div = plotly.offline.plot({
        "data": [plotly.graph_objs.Bar(x=cols_err.tolist(), y=err_vals.tolist())]
    }, include_plotlyjs=False, output_type='div')

    return render_template('detail.html',
        tables=[flow.reset_index(drop=True).transpose().to_html(classes='data')],
        exp=exp.as_html() if exp else None,
        ae_plot=plot_div)

# ==============================================================
# 16. Socket.IO events
# ==============================================================
@socketio.on('connect', namespace='/test')
def test_connect():
    global thread
    print('Client connected')
    if not thread.is_alive():
        print('Starting sniffing thread')
        thread = socketio.start_background_task(snif_and_detect)

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')

# ==============================================================
# 17. Lancement de l'application
# ==============================================================
if __name__ == '__main__':
    socketio.run(app)
