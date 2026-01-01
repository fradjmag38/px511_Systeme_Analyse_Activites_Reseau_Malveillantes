"""
demo_traffic.py
---------------
Génère 2 patterns de trafic TCP pour une démo IDS :

1) benign : quelques connexions "normales" + payload léger + pause
2) burst  : rafale de connexions courtes vers un seul port (pattern suspect)

Usage exemples (les 2 commandes que tu voulais) :
  python demo_traffic.py benign --target 192.168.1.1 --port 80
  python demo_traffic.py burst  --target 192.168.1.1 --port 80

⚠️ Le script refuse les IP publiques.
👉 Choisis comme target :
- l’IP de ton routeur (souvent 192.168.1.1)
- ou un autre appareil de TON réseau (PC, VM, etc.)
"""

import argparse
import ipaddress
import socket
import time


# Deux "exemples" de payload (tu peux les laisser tels quels)
BENIGN_PAYLOAD = b"GET / HTTP/1.1\r\nHost: demo.local\r\nUser-Agent: IDS-Demo/1.0\r\n\r\n"
SUSPICIOUS_PAYLOAD = b"X" * 8  # très petit payload, l'effet vient surtout du burst de connexions


def is_allowed_target(ip: str) -> bool:
    """Autorise uniquement loopback ou IP privées RFC1918."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_private
    except ValueError:
        return False


def one_tcp_connection(target: str, port: int, payload: bytes, timeout: float = 1.0) -> bool:
    """Ouvre une connexion TCP, envoie un payload, et ferme."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.sendall(payload)
            # optionnel: lire une réponse sans bloquer trop
            s.settimeout(0.2)
            try:
                _ = s.recv(256)
            except Exception:
                pass
        return True
    except Exception:
        return False


def benign(target: str, port: int, n: int, pause: float):
    """Trafic normal: quelques connexions espacées, payload type HTTP."""
    ok = 0
    for i in range(n):
        if one_tcp_connection(target, port, BENIGN_PAYLOAD):
            ok += 1
        time.sleep(pause)
    print(f"[benign] done. success={ok}/{n}")


def burst(target: str, port: int, n: int, pause: float):
    """
    Pattern suspect: rafale de connexions très rapprochées vers UN SEUL port.
    (pas de scan multi-ports)
    """
    ok = 0
    for i in range(n):
        if one_tcp_connection(target, port, SUSPICIOUS_PAYLOAD, timeout=0.5):
            ok += 1
        if pause > 0:
            time.sleep(pause)
    print(f"[burst] done. success={ok}/{n}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["benign", "burst"], help="Type de trafic à générer")
    parser.add_argument("--target", required=True, help="IP cible (privée ou 127.0.0.1)")
    parser.add_argument("--port", type=int, default=80, help="Port TCP cible (défaut 80)")
    parser.add_argument("--count", type=int, default=None, help="Nb de connexions (optionnel)")
    parser.add_argument("--pause", type=float, default=None, help="Pause entre connexions en secondes (optionnel)")
    args = parser.parse_args()

    if not is_allowed_target(args.target):
        raise SystemExit("Refus: target doit être une IP privée (RFC1918) ou 127.0.0.1")

    # Valeurs par défaut selon le mode
    if args.mode == "benign":
        count = args.count if args.count is not None else 10
        pause = args.pause if args.pause is not None else 0.5
        print(f"Running BENIGN: target={args.target}:{args.port} count={count} pause={pause}s")
        benign(args.target, args.port, count, pause)
    else:
        count = args.count if args.count is not None else 100
        pause = args.pause if args.pause is not None else 0.001
        print(f"Running BURST: target={args.target}:{args.port} count={count} pause={pause}s")
        burst(args.target, args.port, count, pause)


if __name__ == "__main__":
    main()