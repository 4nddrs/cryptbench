import os  # Proporciona funciones para interactuar con el sistema operativo
import time  # Permite medir el tiempo de ejecución de los algoritmos
import psutil  # Proporciona información sobre procesos y uso de recursos del sistema
import tracemalloc  # Permite rastrear el uso de memoria
import colorama  # Permite agregar colores a la salida de la consola
from colorama import Fore, Style  # Importa colores y estilos de texto de colorama
from tabulate import tabulate  # Permite formatear datos en tablas legibles

# Importación de algoritmos de cifrado
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # Cifrado ChaCha20-Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Cifrado simétrico AES
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec  # Cifrado asimétrico RSA y ECC
from cryptography.hazmat.primitives import serialization, hashes  # Serialización y funciones hash
from Crypto.Cipher import Blowfish  # Cifrado simétrico Blowfish

from tqdm import tqdm  # Barra de progreso para visualización de procesos largos
import platform  # Proporciona información sobre el sistema operativo
import sys  # Permite interactuar con la configuración del sistema

def print_banner():
    print(Fore.BLUE + "=" * 90)
    print(Fore.CYAN + """ 
░█████╗░██████╗░██╗░░░██╗██████╗░████████╗██████╗░███████╗███╗░░██╗░█████╗░██╗░░██╗
██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗╚══██╔══╝██╔══██╗██╔════╝████╗░██║██╔══██╗██║░░██║
██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝░░░██║░░░██████╦╝█████╗░░██╔██╗██║██║░░╚═╝███████║
██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░░░░██║░░░██╔══██╗██╔══╝░░██║╚████║██║░░██╗██╔══██║
╚█████╔╝██║░░██║░░░██║░░░██║░░░░░░░░██║░░░██████╦╝███████╗██║░╚███║╚█████╔╝██║░░██║
░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚══════╝╚═╝░░╚══╝░╚════╝░╚═╝░░╚═╝ """)
    print(Fore.BLUE + "=" * 90 + Style.RESET_ALL)

# Función para leer un archivo en modo binario
def read_file(filename):
    with open(filename, "rb") as file:
        return file.read()

# Función para escribir datos en un archivo en modo binario
def write_file(filename, data):
    with open(filename, "wb") as file:
        file.write(data)

# Función para limpiar la pantalla de la terminal
def clear_screen():
    if platform.system() == "Windows":
        os.system("cls")  # Comando para limpiar la pantalla en Windows
    else:
        os.system("clear")  # Comando para limpiar la pantalla en sistemas Unix/Linux/Mac

def measure_algorithm(algorithm_name, encrypt_func, decrypt_func, plaintext, iterations=1000):
    process = psutil.Process(os.getpid())  # Obtener el proceso actual
    tracemalloc.start()  # Iniciar el rastreo de memoria
    start_time = time.time()  # Registrar el tiempo de inicio
    cpu_usage_start = process.cpu_percent(interval=None)  # Medir el uso de CPU inicial
    
    # Usar tqdm para mostrar la barra de progreso con colores
    for i in tqdm(
        range(iterations), 
        desc=f"Running {algorithm_name}", 
        ncols=100, 
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed} < {remaining}, {rate_fmt}]",
        colour=(
            "GREEN" if algorithm_name == "ChaCha20-Poly1305" else
            "YELLOW" if algorithm_name == "AES-GCM" else
            "MAGENTA" if algorithm_name == "Blowfish" else
            "CYAN" if algorithm_name == "RSA" else
            "BLUE" if algorithm_name == "ECC" else "white"
        )
    ):
        encrypted_data = encrypt_func(plaintext)  # Cifrar los datos
        
        # Para ECC, verificar si la firma es válida
        if algorithm_name == "ECC":
            decrypted_data = decrypt_func(encrypted_data, plaintext)  # Pasar el mensaje original
            assert decrypted_data == b"Signature is valid!", f"Decryption failed for {algorithm_name}"  # Verificar firma válida
        else:
            decrypted_data = decrypt_func(encrypted_data)  # Descifrar los datos
            assert decrypted_data == plaintext, f"Decryption failed for {algorithm_name}"  # Comparar con el texto original

    cpu_usage_end = process.cpu_percent(interval=None)  # Medir el uso de CPU al final
    end_time = time.time()  # Registrar el tiempo de finalización
    current_mem, peak_mem = tracemalloc.get_traced_memory()  # Obtener uso de memoria
    tracemalloc.stop()  # Detener el rastreo de memoria
    
    # Retornar los resultados en una lista
    return [
        algorithm_name,
        f"{(end_time - start_time):.4f} s",  # Tiempo total de ejecución
        f"{(end_time - start_time) / iterations:.6f} s",  # Tiempo promedio por iteración
        f"{peak_mem / 1024:.2f} KB",  # Memoria máxima usada
        f"{(cpu_usage_end - cpu_usage_start):.2f} %"  # Uso de CPU durante la ejecución
    ]

def encrypt_chacha20(plaintext):
    key = os.urandom(32)  # Genera una clave aleatoria de 32 bytes
    nonce = os.urandom(12)  # Genera un nonce aleatorio de 12 bytes
    cipher = ChaCha20Poly1305(key)  # Crea un objeto de encriptación ChaCha20Poly1305
    return cipher.encrypt(nonce, plaintext, None), key, nonce  # Encripta el texto y devuelve el texto cifrado, clave y nonce

def decrypt_chacha20(data):
    ciphertext, key, nonce = data  # Desempaqueta los datos encriptados, la clave y el nonce
    cipher = ChaCha20Poly1305(key)  # Crea un objeto de encriptación ChaCha20Poly1305
    return cipher.decrypt(nonce, ciphertext, None)  # Desencripta el texto cifrado


def encrypt_aes(plaintext):
    key = os.urandom(32)  # Genera una clave aleatoria de 32 bytes
    iv = os.urandom(16)  # Genera un vector de inicialización (IV) aleatorio de 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))  # Crea un objeto de encriptación AES con el modo GCM
    encryptor = cipher.encryptor()  # Crea un objeto para realizar la encriptación
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()  # Encripta el texto y finaliza
    return ciphertext, encryptor.tag, key, iv  # Devuelve el texto cifrado, la etiqueta (tag), la clave y el IV

def decrypt_aes(data):
    ciphertext, tag, key, iv = data  # Desempaqueta los datos encriptados, la etiqueta, la clave y el IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))  # Crea un objeto de encriptación AES con el modo GCM y la etiqueta
    decryptor = cipher.decryptor()  # Crea un objeto para realizar la desencriptación
    return decryptor.update(ciphertext) + decryptor.finalize()  # Desencripta el texto cifrado


def encrypt_blowfish(plaintext):
    key = os.urandom(16)  # Genera una clave aleatoria de 16 bytes
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)  # Crea un objeto de encriptación Blowfish en modo ECB
    return cipher.encrypt(plaintext.ljust(8, b' ')), key  # Encripta el texto y lo devuelve junto con la clave

def decrypt_blowfish(data):
    ciphertext, key = data  # Desempaqueta los datos cifrados y la clave
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)  # Crea un objeto de encriptación Blowfish en modo ECB
    return cipher.decrypt(ciphertext).rstrip(b' ')  # Desencripta el texto y elimina el padding


def encrypt_rsa(plaintext):
    private_key = rsa.generate_private_key(  # Genera una clave privada RSA de 2048 bits
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()  # Obtiene la clave pública correspondiente

    aes_key = os.urandom(32)  # Genera una clave aleatoria de 32 bytes para AES
    iv = os.urandom(16)  # Genera un IV aleatorio de 16 bytes para AES
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))  # Crea un objeto de encriptación AES en modo GCM
    encryptor = cipher.encryptor()  # Crea el objeto para encriptar
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()  # Encripta el texto plano usando AES

    encrypted_aes_key = public_key.encrypt(  # Encripta la clave AES usando la clave pública RSA
        aes_key,
        padding.OAEP(  # Utiliza el esquema de padding OAEP con SHA256
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Devuelve el texto cifrado, la etiqueta de autenticación (tag), el IV, la clave AES cifrada y la clave privada RSA
    return (ciphertext, encryptor.tag, iv, encrypted_aes_key, private_key)



def decrypt_rsa(data):
    ciphertext, tag, iv, encrypted_aes_key, private_key = data  # Desempaqueta los datos

    # Desencripta la clave AES usando la clave privada RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(  # Utiliza el esquema de padding OAEP con SHA256
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Crea un objeto de encriptación AES con la clave AES desencriptada y el IV
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))  # Utiliza GCM para autenticación y descifrado
    decryptor = cipher.decryptor()  # Crea el objeto para desencriptar
    return decryptor.update(ciphertext) + decryptor.finalize()  # Desencripta el texto cifrado y devuelve el resultado


def encrypt_ecc(plaintext):
    private_key = ec.generate_private_key(ec.SECP256R1())  # Genera una clave privada usando SECP256R1
    public_key = private_key.public_key()  # Obtiene la clave pública correspondiente

    signature = private_key.sign(  # Firma el mensaje (plaintext) con la clave privada
        plaintext,
        ec.ECDSA(hashes.SHA256())  # Usa el algoritmo ECDSA con SHA256 para la firma
    )

    return signature, public_key, private_key  # Devuelve la firma, la clave pública y la clave privada


def decrypt_ecc(data, original_message):
    signature, public_key, private_key = data  # Desempaqueta los datos (firma, clave pública y privada)
    
    try:
        # Verifica que la firma es válida usando la clave pública
        public_key.verify(
            signature,  # La firma a verificar
            original_message,  # El mensaje original que fue firmado
            ec.ECDSA(hashes.SHA256())  # Usa ECDSA con SHA256 para la verificación
        )
        return b"Signature is valid!"  # Si la verificación es exitosa, se devuelve un mensaje de éxito
    except Exception as e:
        print(f"Verification failed: {e}")  # Si la verificación falla, se captura la excepción y se muestra el error
        return f"Verification failed: {e}"  # Devuelve un mensaje de fallo con el error


def benchmark_algorithms(plaintext):
    algorithms = [
        ("ECC", encrypt_ecc, decrypt_ecc),
        ("ChaCha20-Poly1305", encrypt_chacha20, decrypt_chacha20),
        ("AES-GCM", encrypt_aes, decrypt_aes),
        ("Blowfish", encrypt_blowfish, decrypt_blowfish),
        ("RSA", encrypt_rsa, decrypt_rsa)
    ]
    results = [measure_algorithm(name, enc, dec, plaintext) for name, enc, dec in algorithms]


    color_map = {
        "ChaCha20-Poly1305": Fore.GREEN,
        "AES-GCM": Fore.YELLOW,
        "Blowfish": Fore.MAGENTA,
        "RSA": Fore.CYAN,
        "ECC": Fore.BLUE
    }

# Aplicar colores a los resultados
    colored_results = []
    for row in results:
        algorithm = row[0]
        color = color_map.get(algorithm, Fore.WHITE)  # Color predeterminado si no está en el diccionario
        colored_row = [color + str(item) + Style.RESET_ALL for item in row]  # Aplicar color a cada celda
        colored_results.append(colored_row)

# Encabezados en negrita y azul
    headers = [Fore.RED + Style.BRIGHT + h + Style.RESET_ALL for h in ["Algorithm", "Total Time", "Avg Time/Iter", "Memory Used", "CPU Load"]]

# Imprimir la tabla con colores
    print(tabulate(colored_results, headers=headers, tablefmt="fancy_grid", stralign="center", numalign="center", colalign=("center", "center", "center", "center", "center")))



    input(Fore.YELLOW + "Presione Enter para continuar..." + Style.RESET_ALL)

def encriptar(palabra, anio_nacimiento):
    """Convierte cada carácter en su valor ASCII y resta el año de nacimiento."""
    return [ord(c) - anio_nacimiento for c in palabra]

def desencriptar(lista_encriptada, anio_nacimiento):
    """Suma el año de nacimiento a cada número para obtener los caracteres originales."""
    return ''.join(chr(num + anio_nacimiento) for num in lista_encriptada)

def ascci():
    """Función principal que maneja la entrada, encriptación y desencriptación."""
    print(Fore.CYAN + "🔷 ENCRIPTADOR ASCII 🔷\n")

    palabra = input(Fore.BLUE + "Ingrese una palabra: ")
    anio_nacimiento = int(input(Fore.BLUE + "Ingrese su año de nacimiento: "))

    # Encriptar
    resultado_encriptado = encriptar(palabra, anio_nacimiento)
    print(Fore.GREEN + "\n🔐 Palabra encriptada:", resultado_encriptado)

    # Desencriptar
    resultado_desencriptado = desencriptar(resultado_encriptado, anio_nacimiento)
    print(Fore.RED + "🔓 Palabra desencriptada:", resultado_desencriptado)

    input(Fore.YELLOW + "\nPresione Enter para continuar..." + Style.RESET_ALL)


def main():
    colorama.init()
    print_banner()
    
    filename = input(Fore.YELLOW + "Ingrese el nombre del archivo a encriptar: " + Style.RESET_ALL)
    plaintext = read_file(filename)
    
    while True:
        clear_screen()
        print_banner()
        print(Fore.GREEN + "\nSeleccione una opción:")
        print(Fore.BLUE + "[1] Ejecutar benchmark de todos los algoritmos")
        print(Fore.BLUE + "[2] Ejecutar algoritmo ASCCI")
        print(Fore.RED + "[0] Salir" + Style.RESET_ALL)
        
        choice = input(Fore.YELLOW + "Ingrese una opción: " + Style.RESET_ALL)
        if choice == "0":
            print(Fore.RED + "Saliendo..." + Style.RESET_ALL)
            break
        elif choice == "1":
            benchmark_algorithms(plaintext)
        elif choice == "2":
            ascci();
        else:
            print(Fore.RED + "Opción inválida." + Style.RESET_ALL)

if __name__ == "__main__":
    main()

