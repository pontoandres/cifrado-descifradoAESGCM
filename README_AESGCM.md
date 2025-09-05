# Cifrador de Archivos AES-GCM (PyCryptodome + scrypt)

Esta herramienta cifra/descifra **cualquier tipo de archivo** usando **AES-256-GCM**, con una clave derivada de la contraseña del usuario mediante **scrypt**.  
Es seguro por defecto (AEAD: confidencialidad + integridad), usa un *nonce* aleatorio de 12B por archivo y procesa datos en bloques para manejar archivos grandes.

---

## ¿Por qué este diseño?
- **AES-GCM (AEAD):** provee cifrado + integridad (tag de autenticación). El descifrado falla si los datos o la contraseña son incorrectos.  
- **scrypt KDF:** deriva una clave fuerte a partir de una contraseña; usa un **salt** aleatorio (almacenado en el encabezado).  
- **Sin dependencias externas** aparte de PyCryptodome; ideal para laboratorios académicos y despliegues ligeros.  
- **Encabezado claro:** incluye metadatos no secretos: `salt`, `nonce`, versión. El **tag** se guarda al final del archivo.  

---

## Formato de archivo
Todos los valores se guardan en bytes:

```
[MAGIC='AESC'(4)] [VERSION=0x01(1)] [SALT(16)] [NONCE(12)] [RESERVED(3)=0]
[CIPHERTEXT(...)] [TAG(16)]
```

- `SALT` y `NONCE` son aleatorios; **no son secretos**.  
- `TAG` autentica todo el ciphertext.  
- Clave derivada con:  
  `scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)` → AES-256.  

---

## Instalación
```bash
python -m venv venv
# Linux/Mac
source venv/bin/activate
# Windows (PowerShell)
.\venv\Scripts\activate

pip install pycryptodome
```

## Uso

### Cifrar
```bash
python aesc.py encrypt --in ruta/al/archivo.ext --out ruta/al/archivo.ext.aes
# Te pedirá la contraseña (entrada oculta).
```
Si ya estás dentro del directorio del archivo, puedes simplificar con:

```bash
cd "C:\ruta\al\archivo"
# por ejemplo cd "C:\Users\pontomoreno\Documents\Trabajos Universidad\ciberseguridad"
python aesc.py encrypt --in nombre_archivo.ext --out nombre_archivo.ext.aes
# nombre_archivo -> es el nombre de tu archivo
# .ext -> es la extension de tu archivo
```
Si tienes exito veras un mensaje en tu terminal de este tipo:
✅ Encrypted: nombre_archivo.ext -> nombre_archivo.ext.aes

### Descifrar
```bash
python aesc.py decrypt --in path/to/file.ext.aes --out path/to/file.ext
# Ingresa la misma contraseña; si es incorrecta o el archivo fue alterado, falla el descifrado.
```
De la misma manera si ya estás dentro del directorio del archivo, puedes simplificar con:
```bash
cd "C:\ruta\al\archivo"
# por ejemplo cd "C:\Users\pontomoreno\Documents\Trabajos Universidad\ciberseguridad"
python aesc.py decrypt --in nombre_archivo.ext.aes --out nombre_archivo_recuperado.ext
# nombre_archivo_recuperado -> es como quieres que sea el nombre del archivo recuperado
# .ext -> es la extension de tu archivo
```
Si tienes exito veras un mensaje en tu terminal de este tipo:
✅ Decrypted: nombre_archivo.ext.aes -> nombre_archivo_recuperado.ext

Encambio si en cualquier paso (cifrar o descifrar) no tienes exito veras un mensaje asi en tu terminal:
❌ Error: {error} donde {error} es el tipo de error que se genero.

## 📝 Notas

- Usa una **contraseña fuerte**.  
- No reutilices el mismo `(clave, nonce)`. Esta herramienta genera un `nonce` aleatorio distinto para cada archivo.  
- Si modificas **un solo byte** del archivo cifrado, el descifrado fallará con *"Authentication failed"*.  
- El tamaño de bloque (`CHUNK_SIZE`) es de 64 KiB; puedes ajustarlo según tus necesidades.  
- El **tag** siempre es de 16 bytes. La versión y los bytes reservados permiten evolucionar el formato en el futuro.  
