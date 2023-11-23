from cryptography.fernet import Fernet
import json
import os
import secrets
import string


def generar_contrasena_segura(longitud=12):
    if longitud < 12:
        raise ValueError("La longitud de la contraseña debe ser al menos de 12 caracteres")

    caracteres = string.ascii_letters + string.digits + string.punctuation
    contrasena = ''.join(secrets.choice(caracteres) for i in range(longitud))

    return contrasena


# Generar una clave de cifrado. Deberías hacerlo una vez y almacenar la clave de forma segura.
def generar_clave_cifrado():
    return Fernet.generate_key()


def guardar_clave_encriptarla_x_tiempo(clave, password_sencillo):
    f = Fernet(clave)
    print(f"clave de encriptacion :{f}\n")
    print(f''' **  AVISO: Esta opción no se recomienda usar por varios motivos!!  **
           - SIEMPRE, se ha de apuntar o copiar la clave maestra en un sitio privado , seguro y ajeno a este sistema.
           - Se guardará la clave maestra enmascarada con una  contraseña a elección por el usuario (fácilmente hackeable). 
           - Dicha contraseña debe recordarse siempre que se quiera recuperar la clave, ya que no existirá registro de dicha palabra. 

           Sin esa contraseña :
                -- No habrá forma de recuperar la clave maestra, desde su lugar de guardado. 
                -- Si además, la clave maestra no fue copiada, ni se tiene escrita o imprimida en otro dispositivo...
                                     NO PODRÁS ACCEDER A NINGUNA CONTRASEÑA.
                    *  *  *                QUE HAYA SIDO ENCRIPTADA CON               *  *  *
                                * * *     UNA CLAVE MAESTRA PERDIDA     * * *   ''')

    password_sencillo = input('Introduce una contraseña facil de recordar, para proteger tu clave..')


# Función para cifrar una contraseña
def cifrar_contrasena(clave, contrasena):
    f = Fernet(clave)
    return f.encrypt(contrasena.encode()).decode()


# Función para descifrar una contraseña
def descifrar_contrasena(clave, contrasena_cifrada):
    f = Fernet(clave)
    return f.decrypt(contrasena_cifrada.encode()).decode()


# Función para guardar la contraseña cifrada
def guardar_contrasena(clave, sitio, contrasena, archivo='contrasenas.json'):
    contrasena_cifrada = cifrar_contrasena(clave, contrasena)
    if os.path.exists(archivo):
        with open(archivo, 'r') as file:
            data = json.load(file)
    else:
        data = {}
    data[sitio] = contrasena_cifrada
    with open(archivo, 'w') as file:
        json.dump(data, file)


# Función para recuperar una contraseña
def recuperar_contrasena(clave, sitio, archivo='contrasenas.json'):
    with open(archivo, 'r') as file:
        data = json.load(file)
    contrasena_cifrada = data.get(sitio)
    if contrasena_cifrada:
        return descifrar_contrasena(clave, contrasena_cifrada)
    return None


# ... (importaciones y definiciones de funciones anteriores)

def guardar_contrasena_modificada(clave, archivo='contrasenas.json'):
    sitio = input("Introduce el nombre del sitio web: ")
    contrasena = generar_contrasena_segura(16)

    if os.path.exists(archivo):
        with open(archivo, 'r') as file:
            data = json.load(file)
    else:
        data = {}

    if sitio in data:
        respuesta = input(f"El sitio {sitio} ya existe. ¿Deseas sobrescribirlo? (s/n): ")
        if respuesta.lower() != 's':
            contador = 1
            nuevo_sitio = f"{sitio}_{contador}"
            while nuevo_sitio in data:
                contador += 1
                nuevo_sitio = f"{sitio}_{contador}"
            sitio = nuevo_sitio

    contrasena_cifrada = cifrar_contrasena(clave, contrasena)
    data[sitio] = contrasena_cifrada
    with open(archivo, 'w') as file:
        json.dump(data, file)

    print(f"Contraseña guardada para el sitio: {sitio}")
    return sitio


# Ejemplo de uso
eleccion = input(
    ' -- Recuperar contraseña?  --->  introduzca URL \n  -- Generar contraseña?  ---> pulse INTRO \n  Teclado  : ...')
if eleccion != "":
    clave_priv = input(f'Introduzca la clave, para recuperar la contraseña de la web : {eleccion} \n')
    mi_contrasena = recuperar_contrasena(clave_priv, eleccion)
    print(f"La contraseña para {eleccion} es: {mi_contrasena}")
else:
    clave_priv = input(' -- Puede usar su password, para acceder a su clave habitual o puede teclearla directamente:  \n'
                       '        - Introduzca su password personal o clave maestra --->   \n\n'
                                                 
                       '        -  o PULSE INTRO ---->  Generar nueva clave de cifrado    \n\n'
    
                                                                                      
                       '                          Teclado : ... \n')
    if clave_priv != "":
        clave = clave_priv
    else:
        clave = generar_clave_cifrado()  # Deberías guardar esta clave en un lugar seguro
        print(
            f' IMPORTANTE! : guarda en lugar seguro esta clave, no aparecerá nunca más: \n =_=_=_=_=   {clave}   =_=_=_=_=\n')

    mi_sitio = guardar_contrasena_modificada(clave)
    # Para recuperar la contraseña, puedes usar la función recuperar_contrasena como antes
    # Recuperar la contraseña
    mi_contrasena = recuperar_contrasena(clave, mi_sitio)
    print(f"La contraseña para {mi_sitio} es: {mi_contrasena}")

'''
# Ejemplo de uso
clave = generar_clave_cifrado()  # Deberías guardar esta clave en un lugar seguro

# Guardar una nueva contraseña
guardar_contrasena(clave, 'mi_sitio_web.com', 'mi_contraseña_segura')

# Recuperar la contraseña
mi_contrasena = recuperar_contrasena(clave, 'mi_sitio_web.com')
print(f"La contraseña para mi_sitio_web.com es: {mi_contrasena}")

# Generar una contraseña segura
contrasena_segura = generar_contrasena_segura(16)  # Puedes cambiar la longitud según tus necesidades
print(f"Contraseña segura generada: {contrasena_segura}")
'''

