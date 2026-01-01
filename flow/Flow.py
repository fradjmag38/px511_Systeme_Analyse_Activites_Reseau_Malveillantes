# Flow.py
# Représentation d'un flow réseau + extraction des features

# ==============================================================
# 1. Imports
# ==============================================================
import statistics
from datetime import datetime

from flow.FlowFeature import FlowFeatures

# Seuil utilisé pour séparer périodes actives / idle (en secondes)
threshold = 5


# ==============================================================
# 2. Classe Flow
# Un Flow représente une communication réseau bidirectionnelle
# ==============================================================
class Flow:

    # ==========================================================
    # 2.1 Initialisation d'un flow à partir du premier paquet
    # ==========================================================
    def __init__(self, packet):

        # --- Stockage des paquets ---
        self.packetInfos = [packet]         # Tous les paquets
        self.fwdPacketInfos = [packet]      # Paquets forward
        self.bwdPacketInfos = []             # Paquets backward

        # --- Initialisation des features ---
        self.flowFeatures = FlowFeatures()
        self.flowFeatures.setDestPort(packet.getDestPort())
        self.flowFeatures.setPID(packet.getPID())
        self.flowFeatures.setPName(packet.getPName())

        # --- Flags TCP ---
        self.flowFeatures.setFwdPSHFlags(0 if not packet.getURGFlag() else 1)
        self.flowFeatures.setFINFlagCount(1 if packet.getFINFlag() else 0)
        self.flowFeatures.setSYNFlagCount(1 if packet.getSYNFlag() else 0)
        self.flowFeatures.setPSHFlagCount(1 if packet.getPSHFlag() else 0)
        self.flowFeatures.setACKFlagCount(1 if packet.getACKFlag() else 0)
        self.flowFeatures.setURGFlagCount(1 if packet.getURGFlag() else 0)

        # --- Tailles et fenêtres TCP ---
        self.flowFeatures.setMaxPacketLen(packet.getPayloadBytes())
        self.flowFeatures.setPacketLenMean(packet.getPayloadBytes())
        self.flowFeatures.setAvgPacketSize(packet.getPacketSize())
        self.flowFeatures.setInitBytesFwd(packet.getWinBytes())

        # --- Infos réseau ---
        self.flowFeatures.setSrc(packet.getSrc())
        self.flowFeatures.setDest(packet.getDest())
        self.flowFeatures.setSrcPort(packet.getSrcPort())
        self.flowFeatures.setProtocol(packet.getProtocol())

        # --- Timestamps ---
        self.flowLastSeen = packet.getTimestamp()
        self.flowStartTime = packet.getTimestamp()
        self.fwdLastSeen = packet.getTimestamp()
        self.bwdLastSeen = 0

        # --- Activité / Inactivité ---
        self.startActiveTime = packet.getTimestamp()
        self.endActiveTime = packet.getTimestamp()

        self.flowIAT = []    # Inter-arrival time global
        self.fwdIAT = []     # IAT forward
        self.bwdIAT = []     # IAT backward
        self.flowActive = [] # Durées actives
        self.flowIdle = []   # Durées idle

        # --- Compteurs ---
        self.packet_count = 1
        self.fwd_packet_count = 1
        self.bwd_packet_count = 0

    # ==========================================================
    # 2.2 Accesseurs
    # ==========================================================
    def getFlowLastSeen(self):
        return self.flowLastSeen

    def getFlowStartTime(self):
        return self.flowStartTime

    # ==========================================================
    # 2.3 Ajout d'un nouveau paquet au flow
    # ==========================================================
    def new(self, packetInfo, direction):

        # ---------------- BACKWARD ----------------
        if direction == 'bwd':
            self.bwdPacketInfos.append(packetInfo)

            if self.bwd_packet_count == 0:
                # Premier paquet backward
                self.flowFeatures.setBwdPacketLenMax(packetInfo.getPayloadBytes())
                self.flowFeatures.setBwdPacketLenMin(packetInfo.getPayloadBytes())
                self.flowFeatures.setInitWinBytesBwd(packetInfo.getWinBytes())
            else:
                self.flowFeatures.setBwdPacketLenMax(
                    max(self.flowFeatures.bwd_packet_len_max, packetInfo.getPayloadBytes()))
                self.flowFeatures.setBwdPacketLenMin(
                    min(self.flowFeatures.bwd_packet_len_min, packetInfo.getPayloadBytes()))
                self.bwdIAT.append((packetInfo.getTimestamp() - self.bwdLastSeen) * 1e6)

            self.bwd_packet_count += 1
            self.bwdLastSeen = packetInfo.getTimestamp()

        # ---------------- FORWARD ----------------
        else:
            self.fwdPacketInfos.append(packetInfo)
            self.fwdIAT.append((packetInfo.getTimestamp() - self.fwdLastSeen) * 1e6)
            self.flowFeatures.setFwdPSHFlags(
                max(1 if packetInfo.getURGFlag() else 0, self.flowFeatures.getFwdPSHFlags())
            )
            self.fwd_packet_count += 1
            self.fwdLastSeen = packetInfo.getTimestamp()

        # ---------------- Mise à jour globale ----------------
        self.flowFeatures.setMaxPacketLen(
            max(self.flowFeatures.getMaxPacketLen(), packetInfo.getPayloadBytes())
        )

        # Flags TCP
        if packetInfo.getFINFlag(): self.flowFeatures.setFINFlagCount(1)
        if packetInfo.getSYNFlag(): self.flowFeatures.setSYNFlagCount(1)
        if packetInfo.getPSHFlag(): self.flowFeatures.setPSHFlagCount(1)
        if packetInfo.getACKFlag(): self.flowFeatures.setACKFlagCount(1)
        if packetInfo.getURGFlag(): self.flowFeatures.setURGFlagCount(1)

        # ---------------- Active / Idle time ----------------
        time = packetInfo.getTimestamp()
        if time - self.endActiveTime > threshold:
            if self.endActiveTime - self.startActiveTime > 0:
                self.flowActive.append(self.endActiveTime - self.startActiveTime)
            self.flowIdle.append(time - self.endActiveTime)
            self.startActiveTime = time
            self.endActiveTime = time
        else:
            self.endActiveTime = time

        # ---------------- Comptage & IAT ----------------
        self.packet_count += 1
        self.packetInfos.append(packetInfo)
        self.flowIAT.append((packetInfo.getTimestamp() - self.flowLastSeen) * 1e6)
        self.flowLastSeen = packetInfo.getTimestamp()

    # ==========================================================
    # 2.4 Fin du flow → calcul final des features
    # ==========================================================
    def terminated(self):

        # --- Durée du flow ---
        duration = (self.flowLastSeen - self.flowStartTime) * 1e6
        self.flowFeatures.setFlowDuration(duration)

        # --- Backward packet statistics ---
        bwd_packet_lens = [x.getPayloadBytes() for x in self.bwdPacketInfos]
        if bwd_packet_lens:
            self.flowFeatures.setBwdPacketLenMean(statistics.mean(bwd_packet_lens))
            if len(bwd_packet_lens) > 1:
                self.flowFeatures.setBwdPacketLenStd(statistics.stdev(bwd_packet_lens))

        # --- Flow IAT ---
        if self.flowIAT:
            self.flowFeatures.setFlowIATMean(statistics.mean(self.flowIAT))
            self.flowFeatures.setFlowIATMax(max(self.flowIAT))
            self.flowFeatures.setFlowIATMin(min(self.flowIAT))
            if len(self.flowIAT) > 1:
                self.flowFeatures.setFlowIATStd(statistics.stdev(self.flowIAT))

        # --- Forward IAT ---
        if self.fwdIAT:
            self.flowFeatures.setFwdIATTotal(sum(self.fwdIAT))
            self.flowFeatures.setFwdIATMean(statistics.mean(self.fwdIAT))
            self.flowFeatures.setFwdIATMax(max(self.fwdIAT))
            self.flowFeatures.setFwdIATMin(min(self.fwdIAT))
            if len(self.fwdIAT) > 1:
                self.flowFeatures.setFwdIATStd(statistics.stdev(self.fwdIAT))

        # --- Backward IAT ---
        if self.bwdIAT:
            self.flowFeatures.setBwdIATTotal(sum(self.bwdIAT))
            self.flowFeatures.setBwdIATMean(statistics.mean(self.bwdIAT))
            self.flowFeatures.setBwdIATMax(max(self.bwdIAT))
            self.flowFeatures.setBwdIATMin(min(self.bwdIAT))
            if len(self.bwdIAT) > 1:
                self.flowFeatures.setBwdIATStd(statistics.stdev(self.bwdIAT))

        # --- Packets per second ---
        self.flowFeatures.setFwdPackets_s(
            0 if duration == 0 else self.fwd_packet_count / (duration / 1e6)
        )

        # --- Packet length statistics ---
        packet_lens = [x.getPayloadBytes() for x in self.packetInfos]
        if packet_lens:
            self.flowFeatures.setPacketLenMean(statistics.mean(packet_lens))
            if len(packet_lens) > 1:
                self.flowFeatures.setPacketLenStd(statistics.stdev(packet_lens))
                self.flowFeatures.setPacketLenVar(statistics.variance(packet_lens))

        # --- Packet sizes ---
        packet_sizes = [x.getPacketSize() for x in self.packetInfos]
        self.flowFeatures.setAvgPacketSize(sum(packet_sizes) / self.packet_count)

        if self.bwd_packet_count != 0:
            self.flowFeatures.setAvgBwdSegmentSize(sum(bwd_packet_lens) / self.bwd_packet_count)

        # --- Active / Idle ---
        if self.flowActive:
            self.flowFeatures.setActiveMin(min(self.flowActive))
        if self.flowIdle:
            self.flowFeatures.setIdleMean(statistics.mean(self.flowIdle))
            self.flowFeatures.setIdleMax(max(self.flowIdle))
            self.flowFeatures.setIdleMin(min(self.flowIdle))
            if len(self.flowIdle) > 1:
                self.flowFeatures.setIdleStd(statistics.stdev(self.flowIdle))

        # ======================================================
        # 2.5 Retour final des features (ordre ML)
        # ======================================================
        return [
            self.flowFeatures.getFlowDuration(),
            self.flowFeatures.getBwdPacketLenMax(),
            self.flowFeatures.getBwdPacketLenMin(),
            self.flowFeatures.getBwdPacketLenMean(),
            self.flowFeatures.getBwdPacketLenStd(),
            self.flowFeatures.getFlowIATMean(),
            self.flowFeatures.getFlowIATStd(),
            self.flowFeatures.getFlowIATMax(),
            self.flowFeatures.getFlowIATMin(),
            self.flowFeatures.getFwdIATTotal(),
            self.flowFeatures.getFwdIATMean(),
            self.flowFeatures.getFwdIATStd(),
            self.flowFeatures.getFwdIATMax(),
            self.flowFeatures.getFwdIATMin(),
            self.flowFeatures.getBwdIATTotal(),
            self.flowFeatures.getBwdIATMean(),
            self.flowFeatures.getBwdIATStd(),
            self.flowFeatures.getBwdIATMax(),
            self.flowFeatures.getBwdIATMin(),
            self.flowFeatures.getFwdPSHFlags(),
            self.flowFeatures.getFwdPackets_s(),
            self.flowFeatures.getMaxPacketLen(),
            self.flowFeatures.getPacketLenMean(),
            self.flowFeatures.getPacketLenStd(),
            self.flowFeatures.getPacketLenVar(),
            self.flowFeatures.getFINFlagCount(),
            self.flowFeatures.getSYNFlagCount(),
            self.flowFeatures.getPSHFlagCount(),
            self.flowFeatures.getACKFlagCount(),
            self.flowFeatures.getURGFlagCount(),
            self.flowFeatures.getAvgPacketSize(),
            self.flowFeatures.getAvgBwdSegmentSize(),
            self.flowFeatures.getInitWinBytesFwd(),
            self.flowFeatures.getInitWinBytesBwd(),
            self.flowFeatures.getActiveMin(),
            self.flowFeatures.getIdleMean(),
            self.flowFeatures.getIdleStd(),
            self.flowFeatures.getIdleMax(),
            self.flowFeatures.getIdleMin(),
            self.flowFeatures.getSrc(),
            self.flowFeatures.getSrcPort(),
            self.flowFeatures.getDest(),
            self.flowFeatures.getDestPort(),
            self.flowFeatures.getProtocol(),
            datetime.fromtimestamp(self.getFlowStartTime()),
            datetime.fromtimestamp(self.getFlowLastSeen()),
            self.flowFeatures.getPName(),
            self.flowFeatures.getPID(),
        ]
