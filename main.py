from tkinter import ttk, filedialog
import tkinter as tk
from PIL import Image, ImageTk


class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Encryption App")
        self.master.geometry("400x600")
        self.file_type = tk.StringVar()
        self.file_path = tk.StringVar()
        self.text_to_encrypt = tk.StringVar()
        self.output_text = tk.StringVar()
        self.key = tk.StringVar()
        self.encryptType = tk.StringVar()
        self.master_style = ttk.Style(master)
        self.master_style.theme_use()
        self.image_label = ttk.Label(self.master)
        self.output_label = ttk.Label(self.master, text="")
        self.secret_text = tk.StringVar()
        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self.master, text="Select File Type:").pack()

        selection = ttk.Combobox(self.master, textvariable=self.file_type)
        selection["values"] = ("Text", "Image")
        selection['state'] = 'readonly'
        selection.pack()
        selection.bind("<<ComboboxSelected>>", self.output_options)

        self.text_frame = ttk.Frame(self.master)
        self.text_options()

        self.image_frame = ttk.Frame(self.master)
        self.image_options()

        ttk.Button(self.master, text="Exit", command=self.master.destroy).pack(side="bottom", pady=(0, 50),
                                                                               fill="x")
        ttk.Button(self.master, text="Clear Output", command=self.clear_output).pack(side="bottom", fill="x")

    def output_options(self, event):
        if self.file_type.get() == "Text":
            self.show_text_options()
        elif self.file_type.get() == "Image":
            self.show_image_options()

    def show_text_options(self):
        self.text_frame.pack()
        self.image_frame.pack_forget()
        self.hide_key_entry()
        self.hide_image_label()
        self.hide_encrypt_buttons()

    def show_image_options(self):
        self.image_frame.pack()
        self.text_frame.pack_forget()
        self.hide_key_entry()
        self.hide_text_entry()
        self.hide_encrypt_buttons()

    def hide_image_label(self):
        self.image_label.configure(image="")
        self.image_label.image = None

    def hide_text_entry(self):
        self.text_entry.forget()

    def hide_key_entry(self):
        self.key_label.forget()
        self.key_entry.forget()

    def hide_encrypt_buttons(self):
        self.encrypt_button.forget()
        self.decrypt_button.forget()
        self.display_button.forget()
        self.output_textbox.forget()
        self.save_button.forget()

    def clear_output(self):
        self.output_text.set("")
        self.output_textbox.delete(1.0, tk.END)
        self.hide_image_label()

    def encrypt_type(self, event):
        if self.encryptType.get() == "Caesar Cipher":
            self.show_key_entry()
        elif self.encryptType.get() == "Vigenere Cipher":
            self.show_key_entry()

    def text_options(self):
        ttk.Label(self.text_frame, text="Select Encryption Method:").pack()

        encrypt_type = ttk.Combobox(self.text_frame, textvariable=self.encryptType)
        encrypt_type["values"] = ("Caesar Cipher", "Vigenere Cipher")
        encrypt_type['state'] = 'readonly'
        encrypt_type.pack()
        encrypt_type.bind("<<ComboboxSelected>>", self.encrypt_type)

        self.option_output = ttk.Label(self.text_frame, text="Select File or Enter Text:")
        self.browse_option = ttk.Button(self.text_frame, text="Browse", command=self.browse_text_file)
        self.key_label = ttk.Label(self.text_frame, text="Enter Key:")
        self.key_entry = ttk.Entry(self.text_frame, textvariable=self.key)
        self.text_entry = ttk.Entry(self.text_frame, textvariable=self.text_to_encrypt, width=60)

        ttk.Label(self.text_frame, text="Output Options:")

        self.encrypt_button = ttk.Button(self.text_frame, text="Encrypt", command=self.encrypt_text)
        self.decrypt_button = ttk.Button(self.text_frame, text="Decrypt", command=self.decrypt_text)
        self.display_button = ttk.Button(self.text_frame, text="Display in Textbox",
                                         command=self.display_output_in_textbox)
        self.save_button = ttk.Button(self.text_frame, text="Save to File", command=self.save_to_file)
        self.output_textbox = tk.Text(self.text_frame, height=10, width=40)

    def image_options(self):
        ttk.Label(self.image_frame, text="Select Encryption Method:").pack()

        encrypt_type = ttk.Combobox(self.image_frame, textvariable=self.encryptType)
        encrypt_type["values"] = ("Steganography",)
        encrypt_type['state'] = 'readonly'
        encrypt_type.pack()
        encrypt_type.bind("<<ComboboxSelected>>", self.encrypt_type)

        ttk.Label(self.image_frame, text="Select Image File:").pack()
        ttk.Entry(self.image_frame, textvariable=self.file_path).pack()
        ttk.Button(self.image_frame, text="Browse", command=self.browse_image_file).pack()

        # Add an entry field for secret data
        ttk.Label(self.image_frame, text="Enter Secret Data:").pack()
        ttk.Entry(self.image_frame, textvariable=self.text_to_encrypt).pack()
        ttk.Button(self.image_frame, text="Browse Secret Data", command=self.browse_secret_data).pack()

        ttk.Button(self.image_frame, text="Encrypt", command=self.encrypt_image).pack()
        ttk.Button(self.image_frame, text="Decrypt", command=self.decrypt_image).pack()
        ttk.Button(self.image_frame, text="Display Image", command=self.display_image).pack()

    # ttk.Button(self.image_frame, text="Save Image", command=self.save_image).pack()

    def browse_secret_data(self):
        secret_data_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if secret_data_path:
            with open(secret_data_path, "r") as file:
                secret_data = file.read()
                self.text_to_encrypt.set(secret_data)

    def browse_text_file(self):
        secret_data_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if secret_data_path:
            with open(secret_data_path, "r") as file:
                secret_data = file.read()
                self.text_to_encrypt.set(secret_data)

    def browse_image_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif")])
        self.file_path.set(file_path)
        self.display_image()  # Automatically display the selected image

    def display_image(self):
        file_path = self.file_path.get()
        if file_path:
            original_image = Image.open(file_path)
            photo = ImageTk.PhotoImage(original_image)
            self.image_label.configure(image=photo)
            self.image_label.image = photo
            self.image_label.pack()

    def encrypt_image(self):
        file_path = self.file_path.get()
        secret_text = self.text_to_encrypt.get()

        if file_path and secret_text:
            image_encryptor = ImageEncryptor()
            encrypted_image = image_encryptor.hide_text(file_path, secret_text)
            encrypted_image.save("encoded_image.png")
            self.display_image()  # Display the encoded image
            self.output_label.config(text="Encryption Successful!")

    def decrypt_image(self):
        file_path = "encoded_image.png"  # Use the encoded image file
        if file_path:
            image_encryptor = ImageEncryptor()
            decoded_text = image_encryptor.reveal_text(file_path)
            self.output_label.config(text=f"Decoded Text: {decoded_text}")

    def display_output_in_textbox(self):
        output_text = self.output_text.get()
        self.output_textbox.delete(1.0, tk.END)
        self.output_textbox.insert(tk.END, output_text)

    def save_to_file(self):
        output_text = self.output_text.get()
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text Files", "*.txt")],
        )

        if file_path:
            with open(file_path, "w") as file:
                file.write(output_text)

    def encrypt_text(self):
        key = self.key_entry.get().encode()
        text = self.text_to_encrypt.get()

        cipher_type = self.encryptType.get()
        result = ""
        if cipher_type == "Caesar Cipher":
            caesar_cipher = CaesarCipher(int(key))
            result = caesar_cipher.encrypt(text)
        elif cipher_type == "Vigenere Cipher":
            vigenere_cipher = VigenereCipher(key.decode())
            result = vigenere_cipher.encrypt(text)
        elif cipher_type == "Steganography":
            file_path = self.file_path.get()
            secret_text = self.text_to_encrypt.get()
            if file_path and secret_text:
                original_image = Image.open(file_path)
                encrypted_image = self.hide_text(original_image, secret_text)
                encrypted_image.save("encoded_image.png")
                self.display_image()  # Display the encoded image
                self.output_label.config(text="Encryption Successful!")
                return

        self.output_text.set(result)

    def decrypt_text(self):
        key = self.key_entry.get().encode()
        text = self.text_to_encrypt.get()

        cipher_type = self.encryptType.get()
        result = ""

        if cipher_type == "Caesar Cipher":
            caesar_cipher = CaesarCipher(int(key))
            result = caesar_cipher.decrypt(text)
        elif cipher_type == "Vigenere Cipher":
            vigenere_cipher = VigenereCipher(key.decode())
            result = vigenere_cipher.decrypt(text)
        elif cipher_type == "Steganography":
            file_path = "encoded_image.png"  # Use the encoded image file
            if file_path:
                encrypted_image = Image.open(file_path)
                decoded_text = self.reveal_text(encrypted_image)
                self.output_label.config(text=f"Decoded Text: {decoded_text}")
                return

        self.output_text.set(result)

    def show_key_entry(self):
        self.hide_encrypt_buttons()
        self.browse_option.pack()
        self.text_entry.pack()
        self.key_label.pack()
        self.key_entry.pack()

        self.encrypt_button.pack()
        self.decrypt_button.pack()
        self.display_button.pack()
        self.output_textbox.pack()
        self.save_button.pack()

    def hide_key_entry(self):
        self.hide_encrypt_buttons()
        self.browse_option.forget()
        self.key_label.forget()
        self.text_entry.forget()
        self.key_entry.forget()
        self.encrypt_button.pack()
        self.decrypt_button.pack()
        self.display_button.pack()
        self.output_textbox.pack()
        self.save_button.pack()


class CaesarCipher:
    def __init__(self, shift):
        self.shift = shift % 26

    def encrypt(self, plaintext):
        result = "".join([chr((ord(char) + self.shift - 65) % 26 + 65) if char.isupper() else chr(
            (ord(char) + self.shift - 97) % 26 + 97) if char.islower() else char for char in plaintext])
        return result

    def decrypt(self, ciphertext):
        result = "".join([chr((ord(char) - self.shift - 65) % 26 + 65) if char.isupper() else chr(
            (ord(char) - self.shift - 97) % 26 + 97) if char.islower() else char for char in ciphertext])
        return result


class VigenereCipher:
    def __init__(self, key):
        self.key = key

    def extend_key(self, text):
        extended_key = self.key
        while len(extended_key) < len(text):
            extended_key += self.key
        return extended_key

    def encrypt(self, plaintext):
        plaintext = plaintext.upper()
        extended_key = self.extend_key(plaintext)
        ciphertext = ""
        for i in range(len(plaintext)):
            if plaintext[i].isalpha():
                shift = ord(extended_key[i]) - ord('A')
                encrypted_char = chr((ord(plaintext[i]) + shift - ord('A')) % 26 + ord('A'))
                ciphertext += encrypted_char
            else:
                ciphertext += plaintext[i]
        return ciphertext

    def decrypt(self, ciphertext):
        ciphertext = ciphertext.upper()
        extended_key = self.extend_key(ciphertext)
        decrypted_text = ""
        for i in range(len(ciphertext)):
            if ciphertext[i].isalpha():
                shift = ord(extended_key[i]) - ord('A')
                decrypted_char = chr((ord(ciphertext[i]) - shift - ord('A')) % 26 + ord('A'))
                decrypted_text += decrypted_char
            else:
                decrypted_text += ciphertext[i]
        return decrypted_text

class ImageEncryptor:
    def hide_text(self, image_path, text):
        original_image = Image.open(image_path)
        width, height = original_image.size
        pixels = original_image.load()

        text_binary = ''.join(format(ord(char), '08b') for char in text)
        text_index = 0

        for i in range(width):
            for j in range(height):
                pixel = list(pixels[i, j])
                for color_channel in range(3):  # Iterate over RGB channels
                    if text_index < len(text_binary):
                        pixel[color_channel] = int(format(pixel[color_channel], '08b')[:-1] + text_binary[text_index],
                                                   2)
                        text_index += 1
                pixels[i, j] = tuple(pixel)

        return original_image

    def reveal_text(self, image_path):
        encrypted_image = Image.open(image_path)
        width, height = encrypted_image.size
        pixels = encrypted_image.load()
        binary_data = ''

        for i in range(width):
            for j in range(height):
                pixel = list(pixels[i, j])
                for color_channel in range(3):
                    binary_data += format(pixel[color_channel], '08b')[-1]

        decoded_text = ''.join(chr(int(binary_data[i:i + 8], 2)) for i in range(0, len(binary_data), 8))
        return decoded_text


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
