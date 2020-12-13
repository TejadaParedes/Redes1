#!/usr/bin/python
'''
    practica3.py
    Programa principal que realiza el análisis de tráfico sobre una traza PCAP.
    Autor: Javier Ramos <javier.ramos@uam.es>
    2020 EPS-UAM
    python3 practica3.py --trace p3.pcap --mac 00:11:88:cc:33:78 --ip_flujo 70.39.159.111 --port_flujo_udp 8343p3

'''


import sys
import argparse
from argparse import RawTextHelpFormatter
import time
import logging
import shlex
import subprocess
import pandas as pd
from io import StringIO
import os
import warnings
warnings.filterwarnings("ignore")
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
from collections import Counter



'''
    Función: calcularECDF
    Entrada:
        -datos: lista con los datos sobre los que calcular la ECDF
    Salida: :
        -datos: lista con los valores x (datos de entrada)
        -y: lista con los valores de probabilidad acumulada para cada dato de entrada
    Descripción:  Esta función recibe una lista de datos y calcula la función empírica de distribución
    acumulada sobre los mismos. Los datos se devuelven listos para ser pintados.
'''
def calcularECDF(datos):
    datos.sort()
    n = len (datos)
    y = [(i-1)/n for i in range(1,n+1)]

    return datos,y



'''
    Función: ejecutarComandoObtenerSalida
    Entrada:
        -comando: cadena de caracteres con el comando a ejecutar
    Salida:
        -codigo_retorno: código numérico que indica el retorno del comando ejecutado.
        Si este valor es 0, entonces el comando ha ejecutado correctamente.
        -salida_retorno: cadena de caracteres con el retorno del comando. Este retorno
        es el mismo que obtendríamos por stdout al ejecutar un comando de terminal.

    Descripción: Esta función recibe una cadena con un comando a ejecutar, lo ejecuta y retorna
    tanto el código de resultado de la ejecución como la salida que el comando produzca por stdout
'''
def ejecutarComandoObtenerSalida(comando):
    proceso = subprocess.Popen(shlex.split(comando), stdout=subprocess.PIPE)
    salida_retorno = ''
    while True:

        salida_parcial = proceso.stdout.readline()
        if salida_parcial.decode() == '' and proceso.poll() is not None:
            break
        if salida_parcial:
            salida_retorno += salida_parcial.decode()
    codigo_retorno = proceso.poll()
    return codigo_retorno,salida_retorno


'''
    Función: pintarECDF
    Entrada:
        -datos: lista con los datos que se usarán para calcular y pintar la ECDF
        -nombre_fichero: cadena de caracteres con el nombre del fichero donde se guardará la imagen
        (por ejemplo figura.png)
        -titulo: cadena de caracteres con el título a pintar en la gráfica
        -titulo_x: cadena de caracteres con la etiqueta a usar para el eje X de la gráfica
        -titulo_y: cadena de caracteres con la etiqueta a usar para el eje Y de la gráfica
    Salida:
        -Nada

    Descripción: Esta función pinta una gráfica ECDF para unos datos de entrada y la guarda en una imagen
'''
def pintarECDF(datos,nombre_fichero,titulo,titulo_x,titulo_y):

    x, y = calcularECDF(datos)
    x.append(x[-1])
    y.append(1)
    fig1, ax1 = plt.subplots()
    plt.step(x, y, '-')
    _ = plt.xticks(rotation=45)
    plt.title(titulo)
    fig1.set_size_inches(12, 10)
    plt.tight_layout()
    plt.locator_params(nbins=20)
    ax1.set_xlabel(titulo_x)
    ax1.set_ylabel(titulo_y)
    plt.savefig(nombre_fichero, bbox_inches='tight')


'''
    Función: pintarSerieTemporal
    Entrada:
        -x: lista de tiempos en formato epoch y granularidad segundos
        -y: lista con los valores a graficar
        -nombre_fichero: cadena de caracteres con el nombre del fichero donde se guardará la imagen
        (por ejemplo figura.png)
        -titulo: cadena de caracteres con el título a pintar en la gráfica
        -titulo_x: cadena de caracteres con la etiqueta a usar para el eje X de la gráfica
        -titulo_y: cadena de caracteres con la etiqueta a usar para el eje Y de la gráfica
    Salida:
        -Nada

    Descripción: Esta función pinta una serie temporal dados unos datos x e y de entrada y la guarda en una imagen
'''
def pintarSerieTemporal(x,y,nombre_fichero,titulo,titulo_x,titulo_y):

    fig1, ax1 = plt.subplots()
    plt.plot(x, y, '-')
    _ = plt.xticks(rotation=45)
    plt.title(titulo)
    fig1.set_size_inches(12, 10)
    plt.gcf().autofmt_xdate()
    plt.gca().xaxis.set_major_locator(mtick.FixedLocator(x))
    plt.gca().xaxis.set_major_formatter(mtick.FuncFormatter(lambda pos,_: time.strftime("%d-%m-%Y %H:%M:%S",time.localtime(pos))))
    plt.tight_layout()
    plt.locator_params(nbins=20)
    ax1.set_xlabel(titulo_x)
    ax1.set_ylabel(titulo_y)
    plt.savefig(nombre_fichero, bbox_inches='tight')


'''
    Función: pintarTarta
    Entrada:
        -etiquetas: lista con cadenas de caracteres que contienen las etiquetas a usar en el gráfico de tarta
        -valores: lista con los valores a graficar
        -nombre_fichero: cadena de caracteres con el nombre del fichero donde se guardará la imagen
        (por ejemplo figura.png)
        -titulo: cadena de caracteres con el título a pintar en la gráfica

    Salida:
        -Nada

    Descripción: Esta función pinta un gráfico de tarta dadas unas etiquetas y valores de entrada y lo guarda en una imagen
'''
def pintarTarta(etiquetas,valores,nombre_fichero,titulo):

    explode = tuple([0.05]*(len(etiquetas)))

    fig1, ax1 = plt.subplots()
    plt.pie(valores, autopct='%1.1f%%', startangle=90, pctdistance=0.85)
    plt.legend(etiquetas, loc="best")
    plt.title(titulo)
    centre_circle = plt.Circle((0,0),0.70,fc='white')
    fig1 = plt.gcf()
    fig1.gca().add_artist(centre_circle)
    fig1.set_size_inches(12, 10)
    ax1.axis('equal')
    plt.tight_layout()
    plt.savefig(nombre_fichero, bbox_inches='tight')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Programa principal que realiza el análisis de tráfico sobre una traza PCAP',
    formatter_class=RawTextHelpFormatter)
    parser.add_argument('--trace', dest='tracefile', default=False,help='Fichero de traza a usar',required=True)
    parser.add_argument('--mac', dest='mac', default=False,help='MAC usada para filtrar',required=True)
    parser.add_argument('--ip_flujo_tcp', dest='ip_flujo_tcp', default=False,help='IP para filtrar por el flujo TCP',required=True)
    parser.add_argument('--port_flujo_udp', dest='port_flujo_udp', default=False,help='Puerto para filtrar por el flujo UDP',required=True)
    parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
    else:
        logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

    #Creamos un directorio a donde volcaremos los resultado e imágenes

    if not os.path.isdir('resultados'):
        os.mkdir('resultados')

    #Ejemplo de ejecución de comando tshark y parseo de salida. Se parte toda la salida en líneas usando el separador \n
    '''
    logging.info('Ejecutando tshark para obtener el número de paquetes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e frame.protocols -Y \'udp\''.format(args.tracefile))
    nlineas = 0
    aux = 0
    for linea in salida.split('\n'):
        if linea != '':
            nlineas +=1

    for linea in salida.split('\n'):
        for p in linea.split(':'):
            if p == 'udp':
                aux +=1


    print('{} paquetes en la traza {} y count {}'.format(nlineas,args.tracefile, aux))
    '''


    #Analisis de protocolos

    logging.info('Ejecutando tshark para obtener el porcentaje de tráfico IPv4 y NO-IPv4')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e frame.number -Y \'ip\''.format(args.tracefile))
    nlineasip = 0
    for linea in salida.split('\n'):
        if linea != '':
            nlineasip +=1

    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e frame.number -Y \'!ip\''.format(args.tracefile))
    nlineasnoip = 0
    for linea in salida.split('\n'):
        if linea != '':
            nlineasnoip +=1
    #calcular porcentajes
    total = nlineasnoip + nlineasip
    pintarTarta(['NO-IPv4', 'IPv4'],[(100*nlineasnoip)/total,(100*nlineasip)/total],'Porcentaje de tráfico IPv4 y NO-IPv4.png','Porcentaje de tráfico IPv4 y NO-IPv4')
    logging.info('###### DONE!')


    logging.info('Ejecutando tshark para obtener el porcentaje de tráfico TPC,UDP y OTROS sobre el tráfico IP')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e frame.protocols'.format(args.tracefile))
    nudp = 0
    ntcp = 0
    total = 0
    for linea in salida.split('\n'):
        for p in linea.split(':'):
            if p == 'udp':
                nudp +=1
            elif p == 'tcp':
                ntcp +=1
        if linea != '':
            total += 1
    otros = total - (ntcp + nudp)
    pintarTarta(['UDP', 'TCP', 'OTROS'],[100*nudp/total, 100*ntcp/total, 100*otros/total],'Porcentaje de tráfico TPC,UDP y OTROS sobre el tráfico IP.png','Porcentaje de tráfico TPC,UDP y OTROS sobre el tráfico IP')
    logging.info('###### DONE!')
    

    #Obtención de top direcciones IP

    logging.info('Ejecutando tshark para obtener los datos del puerto origen IP por bytes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e ip.src -e frame.len -Y \'ip\''.format(args.tracefile))

    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
        if linea != '':
            celda = linea.split('\t')
            if celda[0] in dic:
                tam = int(dic.get(celda[0])) + int(celda[1])
                dic[celda[0]] = tam
            else:
                dic[celda[0]] = int(celda[1])
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
    	e = 100*e/total

    pintarTarta(top5.keys(), lista,'Top5 IP origen por bytes.png','Top5 IP origen por bytes')
    logging.info('###### DONE!')
    
    logging.info('Ejecutando tshark para obtener los datos del puerto origen IP por paquetes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e ip.src -Y \'ip\''.format(args.tracefile))
    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
	    if linea != '':
		    if linea in dic:
			    tam = dic.get(linea) + 1
			    dic[linea] = tam
		    else:
			    dic[linea] = 1
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
	    e = 100*e/total
    
    pintarTarta(top5.keys(), lista,'Top5 IP origen por paquetes.png','Top5 IP origen por paquetes')
    logging.info('###### DONE!')
    
    logging.info('Ejecutando tshark para obtener los datos del puerto destino IP por paquetes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e ip.dst -Y \'ip\''.format(args.tracefile))
    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
        if linea != '':
            if linea in dic:
                tam = dic.get(linea) + 1
                dic[linea] = tam
            else:
                dic[linea] = 1
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
        e = 100*e/total

    pintarTarta(top5.keys(), lista,'Top5 IP destino por paquetes.png','Top5 IP destino por paquetes')
    logging.info('###### DONE!')

    logging.info('Ejecutando tshark para obtener los datos del puerto destino IP por bytes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e ip.dst -e frame.len -Y \'ip\''.format(args.tracefile))

    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
    	if linea != '':
    		celda = linea.split('\t')
    		if celda[0] in dic:
    			tam = int(dic.get(celda[0])) + int(celda[1])
    			dic[celda[0]] = tam
    		else:
    			dic[celda[0]] = int(celda[1])
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
    	e = 100*e/total

    pintarTarta(top5.keys(), lista,'Top5 IP destino por bytes.png','Top5 IP destino por bytes')
    logging.info('###### DONE!')

    #Obtención de top puertos TCP

    logging.info('Ejecutando tshark para obtener los datos del puerto origen TCP por bytes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e tcp.srcport -e frame.len -Y \'tcp\''.format(args.tracefile))

    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
        if linea != '':
            celda = linea.split('\t')
            if celda[0] in dic:
                tam = int(dic.get(celda[0])) + int(celda[1])
                dic[celda[0]] = tam
            else:
                dic[celda[0]] = int(celda[1])
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
    	e = 100*e/total

    pintarTarta(top5.keys(), lista,'Top5 TCP origen por bytes.png','Top5 TCP origen por bytes')
    logging.info('###### DONE!')

    #TODO: Añadir código para obtener los datos y generar la gráfica de top puerto origen TCP por paquetes
    logging.info('Ejecutando tshark para obtener los datos del puerto origen TCP por paquetes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e tcp.srcport -Y \'tcp\''.format(args.tracefile))

    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
        if linea != '':
            if linea in dic:
                tam = dic.get(linea) + 1
                dic[linea] = tam
            else:
                dic[linea] = 1
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
    	e = 100*e/total

    pintarTarta(top5.keys(), lista,'Top5 TCP origen por paquetes.png','Top5 TCP origen por paquetes')
    logging.info('###### DONE!')

    #TODO: Añadir código para obtener los datos y generar la gráfica de top puerto destino TCP por paquetes
    logging.info('Ejecutando tshark para obtener los datos del puerto destino TCP por paquetes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e tcp.dstport -Y \'tcp\''.format(args.tracefile))

    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
        if linea != '':
            if linea in dic:
            	tam = dic.get(linea) + 1             
            	dic[linea] = tam
            else:
            	dic[linea] = 1           
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
    	e = 100*e/total

    pintarTarta(top5.keys(), lista,'Top5 TCP destino por paquetes.png','Top5 TCP destino por paquetes')
    logging.info('###### DONE!')

    #TODO: Añadir código para obtener los datos y generar la gráfica de top puerto destino TCP por bytes
    logging.info('Ejecutando tshark para obtener los datos del puerto destino TCP por bytes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e tcp.dstport -e frame.len -Y \'tcp\''.format(args.tracefile))

    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
        if linea != '':
            celda = linea.split('\t')
            if celda[0] in dic:
                tam = int(dic.get(celda[0])) + int(celda[1])
                dic[celda[0]] = tam
            else:
                dic[celda[0]] = int(celda[1])
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
        e = 100*e/total

    pintarTarta(top5.keys(), lista,'Top5 TCP destino por bytes.png','Top5 TCP destino por bytes')
    logging.info('###### DONE!')

    #Obtención de top puertos UDP
    #TODO: Añadir código para obtener los datos y generar la gráfica de top puerto origen UDP por bytes
    logging.info('Ejecutando tshark para obtener los datos del puerto origen UDP por bytes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e udp.srcport -e frame.len -Y \'udp\''.format(args.tracefile))

    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
        if linea != '':
            celda = linea.split('\t')
            if celda[0] in dic:
                tam = int(dic.get(celda[0])) + int(celda[1])
                dic[celda[0]] = tam
            else:
                dic[celda[0]] = int(celda[1])
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
    	e = 100*e/total

    pintarTarta(top5.keys(), lista,'Top5 UDP origen por bytes.png','Top5 UDP origen por bytes')
    logging.info('###### DONE!')

    #TODO: Añadir código para obtener los datos y generar la gráfica de top puerto destino UDP por bytes
    logging.info('Ejecutando tshark para obtener los datos del puerto destino UDP por bytes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e udp.dstport -e frame.len -Y \'udp\''.format(args.tracefile))
    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
        if linea != '':
            celda = linea.split('\t')
            if celda[0] in dic:
                tam = int(dic.get(celda[0])) + int(celda[1])
                dic[celda[0]] = tam
            else:
                dic[celda[0]] = int(celda[1])
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
        e = 100*e/total

    pintarTarta(top5.keys(), lista,'Top5 UDP destino por bytes.png','Top5 UDP destino por bytes')
    logging.info('###### DONE!')

    #TODO: Añadir código para obtener los datos y generar la gráfica de top puerto origen UDP por paquetes
    logging.info('Ejecutando tshark para obtener los datos del puerto origen UDP por paquetes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e udp.srcport -Y \'udp\''.format(args.tracefile))

    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
        if linea != '':
            if linea in dic:
                tam = dic.get(linea) + 1
                dic[linea] = tam
            else:
                dic[linea] = 1
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
    	e = 100*e/total

    pintarTarta(top5.keys(), lista,'Top5 UDP origen por paquetes.png','Top5 UDP origen por paquetes')
    logging.info('###### DONE!')

    #TODO: Añadir código para obtener los datos y generar la gráfica de top puerto destino UDP por paquetes
    logging.info('Ejecutando tshark para obtener los datos del puerto destino UDP por paquetes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e udp.dstport -Y \'udp\''.format(args.tracefile))

    dic = {}
    top5 = {}
    for linea in salida.split('\n'):
    	if linea != '':
    		if linea in dic:
    			tam = dic.get(linea) + 1
    			dic[linea] = tam
    		else:
    			dic[linea] = 1
    top5 = dict(Counter(dic).most_common(5))
    total = sum(top5.values())
    lista = top5.values()
    for e in lista:
    	e = 100*e/total

    pintarTarta(top5.keys(), lista,'Top5 UDP destino por paquetes.png','Top5 UDP destino por paquetes')
    logging.info('###### DONE!')

    #Obtención de series temporales de ancho de banda

    logging.info('Ejecutando tshark para obtener el ancho de banda con la direccion MAC como origen')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e frame.number -e frame.len -e frame.time_epoch -Y \'eth.src == 00:11:88:CC:33:78\''.format(args.tracefile))
    nLineas = 0
    linea_ant = ""
    for linea in salida.split('\n'):
        if linea != '':
            linea_ant = linea

    ultimo_time = int(float(linea_ant.split("\t")[2]))
    prime_time = 0

    for linea in salida.split('\n'):
        if linea != '':
            prime_time = int(float(linea.split("\t")[2]))
            break

    tam = (1 + (ultimo_time - prime_time))
    serie = [0] * tam

    for linea in salida.split('\n'):
        if linea != '':
            reg = linea.split('\t')
            posicion = int(float(reg[2])) - prime_time
            serie[posicion] = serie[posicion] + int(reg[1])

    xaxis = list(range(prime_time, prime_time + tam))
    pintarSerieTemporal(xaxis, serie, "Ancho_Banda_MACOrigen", "Ancho de banda", "tiempo(s)", "bytes/segundo")
    logging.info('###### DONE!')

    logging.info('Ejecutando tshark para obtener el ancho de banda con la direccion MAC como destino')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e frame.number -e frame.len -e frame.time_epoch -Y \'eth.dst == 00:11:88:CC:33:78\''.format(args.tracefile))
    nLineas = 0
    linea_ant = ""

    for linea in salida.split('\n'):
        if linea != '':
            linea_ant = linea

    ultimo_time = int(float(linea_ant.split("\t")[2]))
    prime_time = 0

    for linea in salida.split('\n'):
        if linea != '':
            prime_time = int(float(linea.split("\t")[2]))
            break

    tam = (1 + (ultimo_time - prime_time))
    serie = [0] * tam

    for linea in salida.split('\n'):
        if linea != '':
            reg = linea.split('\t')
            posicion = int(float(reg[2])) - prime_time
            serie[posicion] = serie[posicion] + int(reg[1])

    xaxis = list(range(prime_time, prime_time + tam))
    pintarSerieTemporal(xaxis, serie, "Ancho_Banda_MACDestino", "Ancho de banda", "tiempo(s)", "bytes/segundo")
    logging.info('###### DONE!')

    #Obtención de las ECDF de tamaño de los paquetes
    
    logging.info('Ejecutando tshark para obtener la cantidad de veces que se repite cada tamanyo de paquete')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e frame.len -Y \'eth.addr == 00:11:88:CC:33:78\''.format(args.tracefile))

    lista_tamanyoPaquetes = []
    for linea in salida.split('\n'):
        linea = linea.strip()
        if linea != '':
            lista_tamanyoPaquetes.append(int(linea))
    pintarECDF(lista_tamanyoPaquetes, "ECDF_tamaño_paquetes_nivel2", "ECDF_tamaño_paquetes_nivel2", "tamaño paquete (bytes)", "probabilidad")
    logging.info('###### DONE!')

    #Obtención de las ECDF de tamaño de los tiempos entre llegadas
    
    logging.info('Ejecutando tshark para obtener el tamaño de los tiempos entre llegadas de los paquetes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e frame.time_delta -Y \'tcp\''.format(args.tracefile))
    
    lista_tiempoPaquetes = []
    primera_linea = True
    tiempo_previo = 0.0
    for linea in salida.split('\n'):
        linea = linea.strip()
        if linea != '':
            lista_tiempoPaquetes.append(float(linea))

    pintarECDF(lista_tiempoPaquetes[:5], "ECDF_tiempo_paquetes_TCP_muestrarioReducido", "ECDF tiempo paquetes TCP", "tiempo entre paquete (s)", "probabilidad")
    pintarECDF(lista_tiempoPaquetes, "ECDF_tiempo_paquetes_TCP", "ECDF tiempo paquetes TCP", "tiempo entre paquete (s)", "probabilidad")
    logging.info('###### DONE!')

    logging.info('Ejecutando tshark para obtener el tamaño de los tiempos entre llegadas de los paquetes')
    codigo,salida = ejecutarComandoObtenerSalida('tshark -r {} -T fields -e frame.time_delta -Y \'udp\''.format(args.tracefile))
    
    lista_tiempoPaquetes = []
    primera_linea = True
    tiempo_previo = 0.0
    for linea in salida.split('\n'):
        inea = linea.strip()
        if linea != '':
            lista_tiempoPaquetes.append(float(linea))

    pintarECDF(lista_tiempoPaquetes[:5], "ECDF_tiempo_paquetes_UDP_muestrarioReducido", "ECDF tiempo paquetes UDP", "tiempo entre paquete (s)", "probabilidad")
    pintarECDF(lista_tiempoPaquetes, "ECDF_tiempo_paquetes_UDP", "ECDF tiempo paquetes UDP", "tiempo entre paquete (s)", "probabilidad")
    logging.info('###### DONE!')
