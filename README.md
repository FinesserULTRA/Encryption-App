#Encryption App
The Encryption App is a Python application that provides a user-friendly interface for encrypting and decrypting text and images using different encryption methods. The application supports Caesar Cipher, Vigenere Cipher, and Image Steganography for secure text and image communication.

Requirements
Python 3.x: The application is written in Python. Make sure you have Python 3.x installed on your system.

Tkinter: Tkinter is used for creating the graphical user interface (GUI). It is usually included with Python installations.

Pillow (PIL Fork): Pillow is used for image processing. You can install it using the following command:

bash
Copy code
pip install Pillow
Installation
Clone the Repository:

bash
Copy code
git clone https://github.com/FinesserULTRA/Encryption-App.git
cd Encryption-App
Install Dependencies:

bash
Copy code
pip install -r requirements.txt
Usage
Run the Application:

bash
Copy code
python Encryption_App.py
Select File Type:

Upon running the application, a window will appear. Select the file type (Text or Image) using the dropdown menu.
Choose Encryption Method:

Choose the encryption method from the available options (Caesar Cipher, Vigenere Cipher, Steganography).
Follow On-Screen Instructions:

Depending on your choices, the application will prompt you to enter a key, select a file, or provide text input.
Encryption/Decryption:

Click the appropriate buttons (Encrypt/Decrypt) to perform the encryption or decryption.
View and Save Results:

Encrypted/decrypted text or images can be displayed on the GUI. You can also save the results to a file using the provided buttons.
Encryption Methods
Text Encryption/Decryption

Caesar Cipher:
Shifts each letter in the text by a fixed number of positions.

Vigenere Cipher:
Encrypts the text using a keyword.


Image Encryption/Decryption (Steganography)

Steganography:
Hides text data within the RGB channels of an image.
#needs fix. doesnt work

Additional Notes
The application allows users to browse for text files or image files.
Encrypted data can be displayed, saved to a file, or used for further processing.
need to work on image one, it is quite buggy and doesnt work


Contributors
Mustafa Hamad
Sohaib Sarwar
Musab Abdullah

License
This project is licensed under the MIT License - see the LICENSE file for details.
