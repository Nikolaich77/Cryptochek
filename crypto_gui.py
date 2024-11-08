import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.x509 import Name, NameAttribute, CertificateBuilder
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime

# Створення директорії для збереження ключів
if not os.path.exists("keys"):
    os.makedirs("keys")

# Створення сертифікату
def generate_certificate(private_key, public_key):
    subject = issuer = Name([NameAttribute(NameOID.COUNTRY_NAME, u"UA"),
                             NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Lviv"),
                             NameAttribute(NameOID.LOCALITY_NAME, u"Lviv"),
                             NameAttribute(NameOID.ORGANIZATION_NAME, u"Cryptochek"),
                             NameAttribute(NameOID.COMMON_NAME, u"Cryptochek RSA Key")])

    cert = CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key).serial_number(
        1000).not_valid_before(datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False).sign(private_key, hashes.SHA256(),
                                                                                         default_backend())
    
    with open("keys/rsa_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("Сертифікат згенеровано та збережено як rsa_certificate.pem")

# Функції для генерації RSA ключів
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Збереження ключів в файли
    with open("keys/rsa_private_key.pem", "wb") as private_pem:
        private_pem.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("keys/rsa_public_key.pem", "wb") as public_pem:
        public_pem.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Генерація та збереження сертифікату
    generate_certificate(private_key, public_key)

    return private_key, public_key

# Функція для шифрування та розшифрування RSA
def encrypt_message_rsa(public_key, message):
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message_rsa(private_key, encrypted_message):
    encrypted_data = base64.b64decode(encrypted_message)
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')

# Функції для шифрування та розшифрування AES
def encrypt_message_aes(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + ' ' * (16 - len(message) % 16)  # Padding
    encrypted = encryptor.update(padded_message.encode('utf-8')) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode('utf-8')

def decrypt_message_aes(key, encrypted_message):
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted.decode('utf-8').rstrip()

# Функції для шифрування та розшифрування 3DES
def encrypt_message_3des(key, message):
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + ' ' * (8 - len(message) % 8)  # Padding
    encrypted = encryptor.update(padded_message.encode('utf-8')) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode('utf-8')

def decrypt_message_3des(key, encrypted_message):
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:8]
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data[8:]) + decryptor.finalize()
    return decrypted.decode('utf-8').rstrip()

# Функція для збереження ключа AES та 3DES в файли
def save_key(file_name, key):
    with open(f"keys/{file_name}", "wb") as key_file:
        key_file.write(key)

# Функція для надсилання електронного листа
def send_email(receiver_email, subject, body):
    sender_email = "kolya.havryluik@gmail.com"
    sender_password = "ylka iqci yhgx twhc"  # Замініть на свій пароль

    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

# Інтерфейс Tkinter
class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto GUI")
        
        self.private_key, self.public_key = generate_keys()
        self.aes_key = os.urandom(32)  # AES 256-bit key
        self.des_key = os.urandom(24)  # Triple DES 192-bit key
        
        # Збереження AES та 3DES ключів
        save_key("aes_key.bin", self.aes_key)
        save_key("3des_key.bin", self.des_key)
        
        print("RSA Private Key:")
        with open("keys/rsa_private_key.pem", "r") as f:
            print(f.read())

        print("RSA Public Key:")
        with open("keys/rsa_public_key.pem", "r") as f:
            print(f.read())

        print(f"AES Key: {base64.b64encode(self.aes_key).decode('utf-8')}")
        print(f"3DES Key: {base64.b64encode(self.des_key).decode('utf-8')}")
        
        # Поле для введення тексту повідомлення
        tk.Label(root, text="Введіть повідомлення:").pack()
        self.message_entry = tk.Entry(root, width=50)
        self.message_entry.pack()
        
        # Поле для електронної пошти отримувача
        tk.Label(root, text="Введіть пошту отримувача:").pack()
        self.email_entry = tk.Entry(root, width=50)
        self.email_entry.pack()
        
        # Вибір алгоритму шифрування
        tk.Label(root, text="Оберіть алгоритм шифрування:").pack()
        self.algorithm_var = tk.StringVar(value="RSA")
        tk.Radiobutton(root, text="RSA", variable=self.algorithm_var, value="RSA").pack()
        tk.Radiobutton(root, text="AES", variable=self.algorithm_var, value="AES").pack()
        tk.Radiobutton(root, text="3DES", variable=self.algorithm_var, value="3DES").pack()
        
        # Поле для перегляду зашифрованого повідомлення
        tk.Label(root, text="Зашифроване повідомлення:").pack()
        self.encrypted_message_entry = tk.Entry(root, width=50)
        self.encrypted_message_entry.pack()
        
        # Кнопка для шифрування повідомлення
        self.encrypt_button = tk.Button(root, text="Зашифрувати", command=self.encrypt_message)
        self.encrypt_button.pack()
        
        # Поле для введення зашифрованого повідомлення для дешифрування
        tk.Label(root, text="Введіть зашифроване повідомлення для дешифрування:").pack()
        self.decryption_entry = tk.Entry(root, width=50)
        self.decryption_entry.pack()
        
        # Кнопка для дешифрування повідомлення
        self.decrypt_button = tk.Button(root, text="Дешифрувати", command=self.decrypt_message)
        self.decrypt_button.pack()
        
        # Поле для перегляду дешифрованого повідомлення
        tk.Label(root, text="Дешифроване повідомлення:").pack()
        self.decrypted_message_entry = tk.Entry(root, width=50)
        self.decrypted_message_entry.pack()
        
        # Кнопка для відправлення електронного листа
        self.send_button = tk.Button(root, text="Відправити на пошту", command=self.send_email)
        self.send_button.pack()
    
    def encrypt_message(self):
        message = self.message_entry.get()
        algorithm = self.algorithm_var.get()
        
        if algorithm == "RSA":
            encrypted_message = encrypt_message_rsa(self.public_key, message)
        elif algorithm == "AES":
            encrypted_message = encrypt_message_aes(self.aes_key, message)
        else:
            encrypted_message = encrypt_message_3des(self.des_key, message)
        
        self.encrypted_message_entry.delete(0, tk.END)
        self.encrypted_message_entry.insert(0, encrypted_message)
        
    def decrypt_message(self):
        encrypted_message = self.decryption_entry.get()
        algorithm = self.algorithm_var.get()
        
        try:
            if algorithm == "RSA":
                decrypted_message = decrypt_message_rsa(self.private_key, encrypted_message)
            elif algorithm == "AES":
                decrypted_message = decrypt_message_aes(self.aes_key, encrypted_message)
            else:
                decrypted_message = decrypt_message_3des(self.des_key, encrypted_message)
            
            self.decrypted_message_entry.delete(0, tk.END)
            self.decrypted_message_entry.insert(0, decrypted_message)
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося дешифрувати: {e}")
        
    def send_email(self):
        receiver_email = self.email_entry.get()
        encrypted_message = self.encrypted_message_entry.get()
        
        subject = "Зашифроване повідомлення"
        body = f"Ваше зашифроване повідомлення: {encrypted_message}"
        
        if send_email(receiver_email, subject, body):
            messagebox.showinfo("Успіх", "Повідомлення надіслано!")
        else:
            messagebox.showerror("Помилка", "Не вдалося надіслати повідомлення.")

# Запуск програми
root = tk.Tk()
app = CryptoApp(root)
root.mainloop()
