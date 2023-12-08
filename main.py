import io

print("Bem vindo ao Cofre de Senhas Super Simplificado e Seguras (confiável!!!!!)")
user_login = input("Digite seu nome de usuário: ")
user_password = input("Digite sua senha: ")

file_name = "login.txt"

try:
    with open(file_name, 'r') as file:
        file_content = file.read()
except FileNotFoundError:
    print(f"File '{file_name}' not found.")
except Exception as e:
    print(f"An error occurred: {e}")