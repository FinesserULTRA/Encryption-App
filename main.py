from tkinter import ttk, filedialog
import tkinter as tk
from PIL import Image, ImageTk


class EncryptionApp:
    def __init__(self, master):
        # Initialize the EncryptionApp
        self.master = master
        self.master.title("Encryption App")
        self.master.geometry("200x200")
        # StringVars to store various inputs
        self.file_type = tk.StringVar()
        self.file_path = tk.StringVar()
        self.text_to_encrypt = tk.StringVar()
        self.output_text = tk.StringVar()
        self.key = tk.StringVar()
        self.encryptType = tk.StringVar()
        # Initialize Tkinter style
        self.master_style = ttk.Style(master)
        self.master_style.theme_use()
        # Label to display images
        self.image_label = ttk.Label(self.master)
        # Label to display output status
        self.output_label = ttk.Label(self.master, text="")
        # StringVar to store secret text
        self.secret_text = tk.StringVar()
        # Create the main UI widgets
        self.create_widgets()

    def create_widgets(self):
        # Label and Combobox for selecting file type
        ttk.Label(self.master, text="Select File Type:").pack()
        selection = ttk.Combobox(self.master, textvariable=self.file_type)
        selection["values"] = ("Text", "Image")
        selection['state'] = 'readonly'
        selection.pack()
        selection.bind("<<ComboboxSelected>>", self.output_options)

        # Frames for Text and Image options
        self.text_frame = ttk.Frame(self.master)
        self.text_options()

        self.image_frame = ttk.Frame(self.master)
        self.image_options()

        # Buttons to exit and clear output
        ttk.Button(self.master, text="Exit", command=self.master.destroy).pack(side="bottom", pady=(0, 35),
                                                                               fill="x")
        ttk.Button(self.master, text="Clear Output", command=self.clear_output).pack(side="bottom", fill="x")

    def output_options(self, event):
        # Display text or image options based on user selection
        if self.file_type.get() == "Text":
            self.show_text_options()
        elif self.file_type.get() == "Image":
            self.show_image_options()

    def show_text_options(self):
        # Display text options, hide image options
        self.master.geometry("400x550")
        self.text_frame.pack()
        self.image_frame.pack_forget()
        self.hide_key_entry()
        self.hide_image_label()
        self.hide_encrypt_buttons()

    def show_image_options(self):
        # Display image options, hide text options
        self.master.geometry("400x550")
        self.image_frame.pack()
        self.text_frame.pack_forget()
        self.hide_key_entry()
        self.hide_text_entry()
        self.hide_encrypt_buttons()

    def hide_image_label(self):
        # Hide the image label
        self.image_label.configure(image="")
        self.image_label.image = None

    def hide_text_entry(self):
        # Forget the text entry widget
        self.text_entry.forget()

    def hide_key_entry(self):
        # Forget key-related widgets
        self.key_label.forget()
        self.key_entry.forget()

    def hide_encrypt_buttons(self):
        # Forget encryption-related buttons and widgets
        self.encrypt_button.forget()
        self.decrypt_button.forget()
        self.display_button.forget()
        self.output_textbox.forget()
        self.save_button.forget()

    def clear_output(self):
        # Clear output labels and text box
        self.output_text.set("")
        self.output_textbox.delete(1.0, tk.END)
        self.hide_image_label()

    def encrypt_type(self, event):
        # Show key entry for selected encryption type
        if self.encryptType.get() == "Caesar Cipher" or self.encryptType.get() == "Vigenere Cipher":
            self.show_key_entry()

    def text_options(self):
        # Text Encryption Options
        ttk.Label(self.text_frame, text="Select Encryption Method:").pack()

        encrypt_type = ttk.Combobox(self.text_frame, textvariable=self.encryptType)
        encrypt_type["values"] = ("Caesar Cipher", "Vigenere Cipher")
        encrypt_type['state'] = 'readonly'
        encrypt_type.pack()
        encrypt_type.bind("<<ComboboxSelected>>", self.encrypt_type)

        # Text Entry Widgets
        self.option_output = ttk.Label(self.text_frame, text="Select File or Enter Text:")
        self.browse_option = ttk.Button(self.text_frame, text="Browse", command=self.browse_text_file)
        self.key_label = ttk.Label(self.text_frame, text="Enter Key:")
        self.key_entry = ttk.Entry(self.text_frame, textvariable=self.key)
        self.text_entry = ttk.Entry(self.text_frame, textvariable=self.text_to_encrypt, width=60)

        # Output Options Widgets
        ttk.Label(self.text_frame, text="Output Options:")

        # Encryption and Output Buttons
        self.encrypt_button = ttk.Button(self.text_frame, text="Encrypt", command=self.encrypt_text)
        self.decrypt_button = ttk.Button(self.text_frame, text="Decrypt", command=self.decrypt_text)
        self.display_button = ttk.Button(self.text_frame, text="Display in Textbox",
                                         command=self.display_output_in_textbox)
        self.save_button = ttk.Button(self.text_frame, text="Save to File", command=self.save_to_file)
        self.output_textbox = tk.Text(self.text_frame, height=10, width=40)

    def image_options(self):
        # Image Encryption Options
        ttk.Label(self.image_frame, text="Select Encryption Method:").pack()

        encrypt_type = ttk.Combobox(self.image_frame, textvariable=self.encryptType)
        encrypt_type["values"] = ("Steganography",)
        encrypt_type['state'] = 'readonly'
        encrypt_type.pack()
        encrypt_type.bind("<<ComboboxSelected>>", self.encrypt_type)

        # Image File Entry
        ttk.Label(self.image_frame, text="Select Image File:").pack()
        ttk.Entry(self.image_frame, textvariable=self.file_path).pack()
        ttk.Button(self.image_frame, text="Browse", command=self.browse_image_file).pack()

        # Add an entry field for secret data
        ttk.Label(self.image_frame, text="Enter Secret Data:").pack()
        ttk.Entry(self.image_frame, textvariable=self.text_to_encrypt).pack()
        ttk.Button(self.image_frame, text="Browse Secret Data", command=self.browse_secret_data).pack()
        ttk.Label(self.image_frame, text="Enter Key:").pack()
        ttk.Entry(self.image_frame, textvariable=self.key).pack()

        # Encryption and Output Buttons
        ttk.Button(self.image_frame, text="Encrypt", command=self.encrypt_image).pack()
        ttk.Button(self.image_frame, text="Decrypt", command=self.decrypt_image).pack()
        ttk.Button(self.image_frame, text="Display Image", command=self.display_image).pack()

    def browse_secret_data(self):
        # Browse for and load secret data
        secret_data_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if secret_data_path:
            with open(secret_data_path, "r") as file:
                secret_data = file.read()
                self.text_to_encrypt.set(secret_data)

    def browse_text_file(self):
        # Browse for and load text file
        secret_data_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if secret_data_path:
            with open(secret_data_path, "r") as file:
                secret_data = file.read()
                self.text_to_encrypt.set(secret_data)

    def browse_image_file(self):
        # Browse for and load image file, then automatically display the selected image
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif")])
        self.file_path.set(file_path)
        self.display_image()

    def display_image(self):
        # Display the selected image
        file_path = self.file_path.get()
        if file_path:
            original_image = Image.open(file_path)
            photo = ImageTk.PhotoImage(original_image)
            self.image_label.configure(image=photo)
            self.image_label.image = photo
            self.image_label.pack()

    def encrypt_image(self):
        # Encrypt image using Steganography
        file_path = self.file_path.get()
        secret_text = self.text_to_encrypt.get()

        if file_path and secret_text:
            image_encryptor = ImageEncryptor()
            encrypted_image = image_encryptor.hide_text(file_path, secret_text)
            encrypted_image.save("encoded_image.png")
            self.display_image()  # Display the encoded image
            self.output_label.config(text="Encryption Successful!")

    def decrypt_image(self):
        # Decrypt image using Steganography
        file_path = "encoded_image.png"  # Use the encoded image file
        if file_path:
            image_encryptor = ImageEncryptor()
            decoded_text = image_encryptor.reveal_text(file_path)
            self.output_label.config(text=f"Decoded Text: {decoded_text}")

    def display_output_in_textbox(self):
        # Display output text in the text box
        output_text = self.output_text.get()
        self.output_textbox.delete(1.0, tk.END)
        self.output_textbox.insert(tk.END, output_text)

    def save_to_file(self):
        # Save output text to a file
        output_text = self.output_text.get()
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text Files", "*.txt")],
        )

        if file_path:
            with open(file_path, "w") as file:
                file.write(output_text)

    def encrypt_text(self):
        # Encrypt text using selected cipher type
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
        # Decrypt text using selected cipher type
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
        # Display key-related widgets
        self.hide_encrypt_buttons()
        self.browse_option.pack()
        self.text_entry.pack()
        self.key_label.pack()
        self.key_entry.pack()

        # Encryption and Output Buttons
        self.encrypt_button.pack()
        self.decrypt_button.pack()
        self.display_button.pack()
        self.output_textbox.pack()
        self.save_button.pack()

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
