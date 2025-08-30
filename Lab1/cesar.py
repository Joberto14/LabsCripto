# Promt 

# Crea un simple scrypt de python que haga un cifrado 
# cesar recibiendo como parametros el string a cifrar 
# y el desplazamiento del cesar usando el alfabeto ingles 
# es decir 26 caracteres e imprima el stringi cifrado nada mas ni nada 

import sys

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

if __name__ == "__main__":
    text = sys.argv[1]
    shift = int(sys.argv[2])
    print(caesar_cipher(text, shift))



