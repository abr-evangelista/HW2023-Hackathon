# TODOS #
# Puxar o senhas.txt
# verificar se files n existem pra criar novos users
# transforme as strings da senhas em 

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

public_key_exists = False
passwords_exists = False

# Verifica se o arquivo existe e cria um novo se não existir
if not os.path.exists(PUBLIC_KEY_FILE_NAME):
  with open(PUBLIC_KEY_FILE_NAME, "w") as f:
    f.write("")

if not os.path.exists(PASSWORDS_FILE_NAME):
  with open(PASSWORDS_FILE_NAME, "w") as f:
    f.write("")

public_keys = []
passwords = []

try:
  with open(PUBLIC_KEY_FILE_NAME, 'r') as file:
      for linha in file:
        public_keys.append(linha)
except FileNotFoundError:
  print(f"Arquivo '{PUBLIC_KEY_FILE_NAME}' não encontrado.")
except Exception as e:
    print(f"Ocorreu um erro: {e}")

try:
  with open(PASSWORDS_FILE_NAME, 'r') as file:
    for linha in file:
      passwords.append(linha)
except FileNotFoundError:
    print(f"Arquivo '{PASSWORDS_FILE_NAME}' não encontrado.")
except Exception as e:
    print(f"Ocorreu um erro: {e}")

print(public_keys)
print(passwords)
