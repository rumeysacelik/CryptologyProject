import hashlib
from random import randint
import math
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def main():
    
    prime=23
    generator=5
    bob_key=diffieHelman(prime, generator,15)
    alice_key=diffieHelman(prime, generator,6)
    
    bob_ad=diffieHelman(prime,alice_key, 15)
    alice_ad=diffieHelman(prime,bob_key, 6)

    print()
    
    plaintext = input("Mesajınızı Giriniz : ")
    key=md5_hash(str(bob_ad))
    print() 
    isPaddingRequired = (len(plaintext) % 8 != 0) # gereksiz bit ekleyip eklemeyeceğimize karar veriyoruz
    ciphertext = DESEncryption(key, plaintext, isPaddingRequired)
    
    sk, pk = generate_rsa_keypair(2048) 
    
    bob_rsa=rsa_encrypt(pk, plaintext.encode())
    
    verify=verifytext(sk, plaintext.encode(), bob_rsa)
    
    bobhash=md5_hash(ciphertext)
    print(bobhash)
    Alice(bobhash, ciphertext,bob_ad,alice_ad,verify,key,isPaddingRequired)
        
    print()
    print("Şifreli Mesaj: %r " % ciphertext)
    print()
        
    private_key, public_key = generate_rsa_keypair(2048)


def diffieHelman(prime,generator,pri_key):
    pri_key=(math.pow(generator, pri_key) % prime)
    return pri_key
    
def Alice(bobhash,ciphertext,bob_ad,alice_ad,verify,key,isPaddingRequired):
    if verify==True:
        if bob_ad==alice_ad:
            aliceHash= md5_hash(ciphertext)
            if aliceHash==bobhash:
                print("anahtar doğrulandı")
                print("dijital imza doğrulandı")
                print(DESDecryption(key, ciphertext, isPaddingRequired))
            else:
                print("dijital imza doğrulanmadı")
               
        else:
            print("anahtar doğrulaması yapılamadı")
    else:
        print("imza doğrulanamadı")
       

def DESEncryption(key, text, padding):    
    if padding == True:#gereksiz bit ekleyip eklememe kararı
        text = addPadding(text)
    ciphertext = DES(text, key, padding, True)
    return ciphertext

def DESDecryption(key, text, padding):
    plaintext = DES(text, key, padding, False)

    if padding == True:#gereksiz bit silmeye karar
        return removePadding(plaintext)
    return plaintext

def DES(text, key, padding, isEncrypt):

    # Initializing variables required
    isDecrypt = not isEncrypt
    # Anahtar Oluşturma
    keys = generateKeys(key)

    # Metni 8 baytlık bloklara bölme
    plaintext8byteBlocks = nSplit(text, 8)
    result = []

    # For all 8-byte blocks of text
    for block in plaintext8byteBlocks:

        # Bloğu bit dizisine dönüştürme
        block = stringToBitArray(block)

        # Başlangıç permütasyonunu uygulama
        block = permutation(block, initialPermutationMatrix)

        # Splitting block into two 4 byte (32 bit) sized blocks
        leftBlock, rightBlock = nSplit(block, 32)

        temp = None

        # Her blok için 16 aynı DES Turunun çalıştırılması
        for i in range(16):
            expandedRightBlock = expand(rightBlock, expandMatrix)

            if isEncrypt == True:#şifrelemede ilk anahtardan baslama
                temp = xor(keys[i], expandedRightBlock)
            elif isDecrypt == True:#deşifrelemede son anahtar ile işlem
                temp = xor(keys[15 - i], expandedRightBlock)
            temp = SboxSubstitution(temp)
            temp = permutation(temp, eachRoundPermutationMatrix)
            temp = xor(leftBlock, temp)
            leftBlock = rightBlock
            rightBlock = temp
        result += permutation(rightBlock + leftBlock, finalPermutationMatrix)#döngü bitimi son per.
    finalResult = bitArrayToString(result)#array->string

    return finalResult

def generate_rsa_keypair(key_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return private_key, private_key.public_key()

def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def verifytext(sk,plaintext,rsaplaintext):
    rsaplaintext=rsa_decrypt(sk, rsaplaintext)
    if plaintext==rsaplaintext:
        return True
    else:
        return False
    
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

keyPermutationMatrix1 = [#anahtar permu.
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

keyPermutationMatrix2 = [# anahtar sıkıstırma perm.
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

def generateKeys(key):#her döngüde farklı key
    keys = []
    key = stringToBitArray(key)
    key = permutation(key, keyPermutationMatrix1)
    #(leftBlock->LEFT), (rightBlock->RIGHT)
    leftBlock, rightBlock = nSplit(key, 28)

    for i in range(16):#16 döndürülmüş keyler
        leftBlock, rightBlock = leftShift(leftBlock, rightBlock, SHIFT[i])
        temp = leftBlock + rightBlock
        keys.append(permutation(temp, keyPermutationMatrix2))#döndürülmüs key
    return keys



def SboxSubstitution(bitArray):
    blocks = nSplit(bitArray, 6)
    result = []

    for i in range(len(blocks)):
        block = blocks[i]
        # satır ilk ve son bit toplamı
        row = int( str(block[0]) + str(block[5]), 2 )
        # sutun deg 2,3,4,5 deger binary top
        column = int(''.join([str(x) for x in block[1:-1]]), 2)
        sboxValue = SboxesArray[i][row][column]
        binVal = binValue(sboxValue, 4)
        result += [int(bit) for bit in binVal]
    return result

def addPadding(text):#gereksiz bit ekleme
    paddingLength = 8 - (len(text) % 8)#
    text += chr(paddingLength) * paddingLength
    return text

def removePadding(data):#gereksiz bit silme
    paddingLength = ord(data[-1])
    return data[ : -paddingLength]

def expand(array, table):#genişletme
    return [array[element - 1] for element in table]

def permutation(array, table):
    return [array[element - 1] for element in table]

def leftShift(list1, list2, n):
    return list1[n:] + list1[:n], list2[n:] + list2[:n]

def nSplit(list, n):
    return [ list[i : i + n] for i in range(0, len(list), n)]

def xor(list1, list2):
    return [element1 ^ element2 for element1, element2 in zip(list1,list2)]

def binValue(val, bitSize):

    binVal = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    while len(binVal) < bitSize:# gerekli sayıda gereksiz bit ekleme"0"
        binVal = "0" + binVal
    return binVal

def stringToBitArray(text):#bit lis olusturuyorum
    bitArray = []
    for letter in text:
        binVal = binValue(letter, 8)
        binValArr = [int(x) for x in list(binVal)]
        bitArray += binValArr
    return bitArray

def bitArrayToString(array):
    byteChunks = nSplit(array, 8) #met.dizisini 8 bayta bölme
    stringBytesList = []
    stringResult = ''
    for byte in byteChunks:
        bitsList = []
        for bit in byte:
            bitsList += str(bit)
        stringBytesList.append(''.join(bitsList))#bayt ekleme(string biçiminde)

   # Her byte'ı char'a dönüştürme ve ardından birleştirme
    result = ''.join([chr(int(stringByte, 2)) for stringByte in stringBytesList])
    return result


def md5_hash(text):
    hash_object = hashlib.md5()

    hash_object.update(text.encode())

    hex_md5 = hash_object.hexdigest()

    return hex_md5



initialPermutationMatrix = [#ilk perm.
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]
# genişletme p.
expandMatrix = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]
SboxesArray = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],

    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],

    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],

    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],

    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],

    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],

    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],

    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
]


eachRoundPermutationMatrix = [#p kutusu
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

finalPermutationMatrix = [#16 turun sonunda per.table
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

if __name__ == '__main__':
    main()
    
    
    
    
    