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

def xor_encrypt_decrypt(message, key):
    # Garante que a chave seja repetida até que tenha o mesmo comprimento que a mensagem
    repeated_key = (key * (len(message) // len(key) + 1))[:len(message)]

    # Usa a operação XOR para cifrar ou decifrar
    result = ''.join(chr(ord(m) ^ ord(k)) for m, k in zip(message, repeated_key))

    return result

def XOR(s1,s2):    
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))


print("Bem vindo ao Cofre de Senhas Super Simplificado e Seguras (confiável!!!!!)")

PUBLIC_KEY_FILE_NAME = "public_key.txt" # valor que vai ajudar pra descriptografar as senhas
PASSWORDS_FILE_NAME = "senhas.txt" # senhas do cofre
POP_FILE_NAME = "popular_senha.txt"

if not os.path.exists(PUBLIC_KEY_FILE_NAME) or not os.path.exists(PASSWORDS_FILE_NAME):
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

    LOGIN_HASH = compute_sha256_hash(user_login)
    PASSWORDS_HASH = compute_sha256_hash(user_password)

    CIPHER_HASH = XOR(LOGIN_HASH, PASSWORDS_HASH)

    with open(POP_FILE_NAME, "r+") as f:
        data = f.read().replace('\n', '')
        f.write(xor_encrypt_decrypt(data, CIPHER_HASH))
       
    print("Criamos seu cofre!!")
    


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
