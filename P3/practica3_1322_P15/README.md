# REDES I - Práctica 3
Alejandro Paredes Tejada  
Federico Pérez Fernández  
Pareja: 15  
Grupo: 1322

## Instrucciones
#
Generar datos para la práctica

    python3 practica3.py --trace p3.pcap --mac 00:11:88:cc:33:78 --ip_flujo 70.39.159.111 --port_flujo_udp 8343p3

Ejecutar práctica

    python3 practica3.py

## Criterios de evaluación
#
- [&check;] Fichero leeme.txt bien explicado: 0,5 puntos 

- [&check;] Script (4,5 puntos):
    - Cálculo de porcentajes por protocolos: 0,5 puntos
    - Obtención del top de puertos: 1,5 puntos
    - Obtención del top de direcciones IP: 0,5 puntos
    - Cálculo del caudal/throughput/tasa/ancho de banda por sentido: 0,5 puntos
    - Obtención de la ECDF del tamaño de paquetes : 0,5 puntos:
    - Obtención de la ECDF de los interarrivals/intervalos de los flujos indicados por el generador de PCAP: 1 punto
        - 0,5 puntos, correspondiente al flujo UDP
        - 0,5 puntos, correspondiente al flujo TCP

- [&check;] Memoria (5 puntos):
    - Porcentajes por protocolos: 0,5 puntos
    - Top de puertos: 1,5 puntos
    - Top de direcciones IP: 0,5 puntos
    - Series temporales del caudal/throughput/tasa/ancho de banda por sentido: 1 punto
    - ECDFs del tamaño de paquetes: 0,5 puntos
    - ECDFs de los interarrivals/intervalos de los flujos indicados por el generador de PCAP: 1 punto
        - 0,5 puntos, correspondiente al flujo UDP
        - 0,5 puntos, correspondiente al flujo TCP