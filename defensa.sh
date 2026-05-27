#!/bin/bash

# 1. Limpieza total de reglas previas
iptables -F
iptables -X
iptables -Z

# 2. Establecer política por defecto: Dropear todo lo entrante que no esté explícitamente permitido
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 3. Permitir tráfico de la interfaz Loopback (Localhost) y conexiones ya establecidas
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# =========================================================================
#  MÓDULO COMPLEJO: DETECCIÓN Y BANEO DINÁMICO DE ESCANEOS RECIENTES (NMAP)
# =========================================================================

# Regla Trampa 1: El Puerto Cebo (Honeypot de Puerto Cerrado)
# Si el atacante toca el puerto 1234 (un puerto que nadie debería usar), guardamos su IP en la lista "ESCANEADOR"
iptables -A INPUT -p tcp --dport 1234 -m recent --set --name ESCANEADOR -j DROP

# Regla Trampa 2: Control de ráfagas SYN (Mitigación de Port Scan rápido y DoS)
# Si una IP intenta abrir más de 4 conexiones TCP SYN nuevas en menos de 10 segundos a puertos válidos, sospechamos de escaneo
iptables -A INPUT -p tcp --syn -m recent --set --name INTENTOS
iptables -A INPUT -p tcp --syn -m recent --update --seconds 10 --hitcount 4 --name INTENTOS -m recent --set --name ESCANEADOR -j DROP

# Regla de Ejecución: Bloqueo absoluto a cualquier IP en la lista "ESCANEADOR" durante 60 segundos
# Cada vez que la IP intente enviar otro paquete, el contador de 60 segundos se reinicia (Baneo infinito mientras siga atacando)
iptables -A INPUT -m recent --update --seconds 60 --name ESCANEADOR -j DROP

# 4. Permitir accesos legítimos (Por ejemplo, un servidor web falso en el puerto 80 para simular normalidad)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Registrar en los logs de Linux (dmesg) los intentos de hackeo antes de tirarlos
iptables -A INPUT -m recent --rcheck --name ESCANEADOR -j LOG --log-prefix "[ALERTA INTRUSO IPTABLES]: "
