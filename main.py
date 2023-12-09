# TODOS #
# transforme as strings da senhas em numeros da tabela ascii

import io
import os
import hashlib

def compute_sha256_hash(data):
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()

    # Update the hash object with the bytes-like object
    sha256_hash.update(data.encode('utf-8'))

    # Get the hexadecimal representation of the hash
    hash_result = sha256_hash.hexdigest()

    return hash_result



print("Bem vindo ao Cofre de Senhas Super Simplificado e Seguras (confiável!!!!!)")

while True:
  user_login = input("Digite seu nome de usuário (somente letras minusculas): ")
  user_password = input("Digite sua senha (min 8 caracteres): ")

  if(user_login.islower() == False):
    os.system("clear")
    print("Nome de usuário inválido, tente novamente.")
    continue

  if(len(user_password) < 8):
    os.system("clear")
    print("Senha muito curta, tente novamente.")
    continue

  break

PUBLIC_KEY_FILE_NAME = "public_key.txt" # valor que vai ajudar pra descriptografar as senhas
PASSWORDS_FILE_NAME = "senhas.txt" # senhas do cofre
POPULATE_FILE_NAME = "popular_senha.txt" # arquivo que vai popular as senhas

public_key_exists = False
passwords_exists = False

public_keys = []
passwords = []

# Verifica se o arquivo existe e cria um novo se não existir
if not os.path.exists(PUBLIC_KEY_FILE_NAME):
  with open(PUBLIC_KEY_FILE_NAME, "w") as f:
    f.write("")

if not os.path.exists(PASSWORDS_FILE_NAME):
  with open(PASSWORDS_FILE_NAME, "w") as f:
    f.write("")

if not os.path.exists(POPULATE_FILE_NAME):
  with open(POPULATE_FILE_NAME, "w") as f:
    f.write("")

try:
  with open(PUBLIC_KEY_FILE_NAME, 'r') as file:
      for linha in file:
        public_keys.append(linha)
except FileNotFoundError:
  print(f"Arquivo '{PUBLIC_KEY_FILE_NAME}' não encontrado.")
except Exception as e:
    print(f"Ocorreu um erro: {e}")

fake_credentials = [
    "GOOGLE:\nabc@gmail.com\nsenha123",
    "AMAZON:\ndef@gmail.com\nabre456",
    "FACEBOOK:\nghi@gmail.com\n123senha",
    "TWITTER:\njkl@gmail.com qwerty789",
    "INSTAGRAM:\nmno@gmail.com p@ssw0rd",
    "LINKEDIN:\npqr@gmail.com\nlinkedin123",
    "SNAPCHAT:\nstu@gmail.com\nghost567",
    "MICROSOFT:\nvwx@gmail.com\nwindows10!",
    "APPLE:\nyz@gmail.com\napple1234",
    "YAHOO:\nxyz@gmail.com\nyahoo987"
]

try:
  with open(PASSWORDS_FILE_NAME, 'r') as file:
    for linha in file:
      passwords.append(linha)
except FileNotFoundError:
    print(f"Arquivo '{PASSWORDS_FILE_NAME}' não encontrado.")
except Exception as e:
    print(f"Ocorreu um erro: {e}")

try:
  with open(POPULATE_FILE_NAME, 'w') as file:
    for string in fake_credentials:
      for linha in string.splitlines():
         file.write(linha + "\n")
except FileNotFoundError:
    print(f"Arquivo '{POPULATE_FILE_NAME}' não encontrado.")
except Exception as e:
    print(f"Ocorreu um erro: {e}")

print(public_keys)
print(passwords)
