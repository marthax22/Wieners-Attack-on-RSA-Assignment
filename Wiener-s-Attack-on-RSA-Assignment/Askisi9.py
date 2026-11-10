#Author: marthachd
import math
import base64


# Βοηθητικές συναρτήσεις για συνεχή κλάσματα
def continued_fraction(num: int, den: int) -> list[int]:

    cf = [] #λίστα ακεραίων [a0, a1, ..., an]
    while den:    
        cf.append(num // den) #Υπολογίζει την ανάπτυξη του num/den σε συνεχές κλάσμα
        num, den = den, num % den
    return cf

#Υπολογίζει τις συγκλίνουσες (h_i / k_i) από ανάπτυξη συνεχούς κλάσματος
def convergents(cf: list[int]) -> list[tuple[int, int]]:
  
    convs = [] #λίστα από ζεύγη (h_i, k_i)
    for i, a in enumerate(cf):       #Αναδρομή: h_i = a_i * h_{i-1} + h_{i-2}
                                                #k_i = a_i * k_{i-1} + k_{i-2}
        if i == 0:
            convs.append((a, 1))
        elif i == 1:
            convs.append((a * cf[0] + 1, a))
        else:
            h_prev2, k_prev2 = convs[i - 2]
            h_prev1, k_prev1 = convs[i - 1]
            convs.append((a * h_prev1 + h_prev2,
                          a * k_prev1 + k_prev2))
    return convs



#Επίθεση Wiener
def wiener_attack(e: int, N: int) -> tuple[int | None, int | None, int | None]:

    cf    = continued_fraction(e, N)
    convs = convergents(cf)

    for k, d in convs:
        if k == 0:
            continue

        # Έλεγχος αν φ(N) = (e*d - 1) / k είναι ακέραιος
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k

        # Επίλυση: x² - (N - φ + 1)x + N = 0
        # => p + q = N - φ + 1,  p*q = N
        b    = N - phi + 1
        disc = b * b - 4 * N

        if disc < 0:
            continue

        sqrt_disc = math.isqrt(disc)
        if sqrt_disc * sqrt_disc != disc: # δεν είναι τέλειο τετράγωνο
            continue

        p = (b + sqrt_disc) // 2
        q = (b - sqrt_disc) // 2

        if p * q == N:
            return d, p, q

    return None, None, None



#Αποκωδικοποιεί το base64 string σε λίστα ακεραίων (cipher blocks)
def decode_ciphertext(b64_data: str) -> list[int]:
 
    raw   = base64.b64decode(b64_data).decode("utf-8")
    inner = raw[3:-1]                       # αφαίρεση "C=[" και "]"
    inner = inner.replace("\r\n", ",")      # Οι γραμμές χωρίζονται με \\r\\n 
    return [int(t.strip()) for t in inner.split(",") if t.strip()]


#Αποκρυπτογραφεί κάθε block: m_i = c_i^d mod N
def decrypt_blocks(cipher_blocks: list[int], d: int, N: int) -> list[int]: 
    return [pow(c, d, N) for c in cipher_blocks]


def numbers_to_text(numbers: list[int]) -> str: #Μετατρέπει λίστα ASCII τιμών σε χαρακτήρες 
    return "".join(chr(m) for m in numbers)


# Κύριο πρόγραμμα
N = 194749497518847283 #Δεδομένα της άσκησης
e = 50736902528669041

#Κρυπτογραφημένο μήνυμα
ciphertext = (
        "Qz1bNDc0MDYyNjMxOTI2OTM1MDksNTEwNjUxNzgyMDExNzIyMjMsMzAyNjA1NjUyMzUxMjg3"
        "MDQsODIzODU5NjMzMzQ0MDQyNjgNCjgxNjkxNTY2NjM5Mjc5MjksNDc0MDYyNjMxOTI2OTM1"
        "MDksMTc4Mjc1OTc3MzM2Njk2NDQyLDEzNDQzNDI5NTg5NDgwMzgwNg0KMTEyMTExNTcxODM1"
        "NTEyMzA3LDExOTM5MTE1MTc2MTA1MDg4MiwzMDI2MDU2NTIzNTEyODcwNCw4MjM4NTk2MzMz"
        "NDQwNDI2OA0KMTM0NDM0Mjk1ODk0ODAzODA2LDQ3NDA2MjYzMTkyNjkzNTA5LDQ1ODE1MzIw"
        "OTcyNTYwMjAyLDE3NDYzMjIyOTMxMjA0MTI0OA0KMzAyNjA1NjUyMzUxMjg3MDQsNDc0MDYy"
        "NjMxOTI2OTM1MDksMTE5MzkxMTUxNzYxMDUwODgyLDU3MjA4MDc3NzY2NTg1MzA2DQoxMzQ0"
        "MzQyOTU4OTQ4MDM4MDYsNDc0MDYyNjMxOTI2OTM1MDksMTE5MzkxMTUxNzYxMDUwODgyLDQ3"
        "NDA2MjYzMTkyNjkzNTA5DQoxMTIxMTE1NzE4MzU1MTIzMDcsNTI4ODI4NTEwMjYwNzI1MDcs"
        "MTE5MzkxMTUxNzYxMDUwODgyLDU3MjA4MDc3NzY2NTg1MzA2DQoxMTkzOTExNTE3NjEwNTA4"
        "ODIsMTEyMTExNTcxODM1NTEyMzA3LDgxNjkxNTY2NjM5Mjc5MjksMTM0NDM0Mjk1ODk0ODAz"
        "ODA2DQo1NzIwODA3Nzc2NjU4NTMwNiw0NzQwNjI2MzE5MjY5MzUwOSwxODU1ODIxMDUyNzUw"
        "NTA5MzIsMTc0NjMyMjI5MzEyMDQxMjQ4DQoxMzQ0MzQyOTU4OTQ4MDM4MDYsODIzODU5NjMz"
        "MzQ0MDQyNjgsMTcyNTY1Mzg2MzkzNDQzNjI0LDEwNjM1NjUwMTg5MzU0NjQwMQ0KODE2OTE1"
        "NjY2MzkyNzkyOSw0NzQwNjI2MzE5MjY5MzUwOSwxMDM2MTA1OTcyMDYxMDgxNiwxMzQ0MzQy"
        "OTU4OTQ4MDM4MDYNCjExOTM5MTE1MTc2MTA1MDg4MiwxNzI1NjUzODYzOTM0NDM2MjQsNDc0"
        "MDYyNjMxOTI2OTM1MDksODE2OTE1NjY2MzkyNzkyOQ0KNTI4ODI4NTEwMjYwNzI1MDcsMTE5"
        "MzkxMTUxNzYxMDUwODgyLDgxNjkxNTY2NjM5Mjc5MjksNDc0MDYyNjMxOTI2OTM1MDkNCjQ1"
        "ODE1MzIwOTcyNTYwMjAyLDE3NDYzMjIyOTMxMjA0MTI0OCwzMDI2MDU2NTIzNTEyODcwNCw0"
        "NzQwNjI2MzE5MjY5MzUwOQ0KNTI4ODI4NTEwMjYwNzI1MDcsMTE5MzkxMTUxNzYxMDUwODgy"
        "LDExMTUyMzQwODIxMjQ4MTg3OSwxMzQ0MzQyOTU4OTQ4MDM4MDYNCjQ3NDA2MjYzMTkyNjkz"
        "NTA5LDExMjExMTU3MTgzNTUxMjMwNyw1Mjg4Mjg1MTAyNjA3MjUwNywxMTkzOTExNTE3NjEw"
        "NTA4ODINCjU3MjA4MDc3NzY2NTg1MzA2LDExOTM5MTE1MTc2MTA1MDg4MiwxMTIxMTE1NzE4"
        "MzU1MTIzMDcsODE2OTE1NjY2MzkyNzkyOQ0KMTM0NDM0Mjk1ODk0ODAzODA2LDU3MjA4MDc3"
        "NzY2NTg1MzA2XQ=="
    )

print("Επίθεση Wiener")

print(f"\n  N = {N}")
print(f"  e = {e}\n")

#Wiener
print("Το ιδιωτικό κλειδί d είναι:")

d, p, q = wiener_attack(e, N)

if d is None:
    print("Η επίθεση Wiener απέτυχε.")
    
print(f"  d = {d}")


#Αποκρυπτογράφηση

cipher_blocks= decode_ciphertext(ciphertext)

plain_numbers= decrypt_blocks(cipher_blocks, d, N)


message= numbers_to_text(plain_numbers)
print("\n")
print("Αρχικό μήνυμα :")
print(f"{message.strip()}")


