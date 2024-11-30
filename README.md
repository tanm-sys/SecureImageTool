# SecureImageTool
A Python application that securely encrypts and decrypts images using AES encryption. Protect your sensitive image data with robust security features, ensuring confidentiality and integrity.

Absolutely! Here is a more detailed and professional README.md for the `SecureImageTool` repository:

---

# Secure Image Tool

This Python application encrypts and decrypts images using AES (Advanced Encryption Standard) in CBC mode, providing a secure way to protect your image data. The tool ensures that sensitive information remains confidential by leveraging robust encryption techniques.

## Table of Contents

1. [Getting Started](#getting-started)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Advanced Features](#advanced-features)
6. [Contributing](#contributing)
7. [License](#license)

## Getting Started

### System Requirements

Before you begin, ensure that your environment meets the following requirements:

- **Python 3.x**: The application is written in Python and requires version 3.x.
- **tkinter** for GUI elements: This comes pre-installed with most Python installations. If not available, it can be installed using `pip`.
- **Pillow**: A fork of PIL (Python Imaging Library) that adds image file handling capabilities. You can install it via pip:

    ```sh
    pip install Pillow
    ```

## Installation

1. Clone this repository or download the files.
2. Navigate to the directory containing the Python script:
    
    ```sh
    cd path/to/SecureImageTool/
    ```
3. Run the application using Python 3.x interpreter:

    ```sh
    python SecureImageTool.py
    ```

### Installation via Virtual Environment

1. Create a virtual environment if you haven't already done so:
    
    ```sh
    python3 -m venv env_name
    ```

2. Activate the virtual environment:

   - **For macOS/Linux**:
     ```sh
     source env_name/bin/activate
     ```
   - **For Windows**:
     ```sh
     .\env_name\Scripts\activate
     ```

3. Install the required dependencies within the virtual environment:
    
    ```sh
    pip install Pillow pycryptodome
    ```

## Dependencies

The following libraries are required for this project:

1. `tkinter` - For building the graphical user interface (GUI).
2. `Pillow` - To handle image operations, specifically converting an image into bytes.
3. `pycryptodome` - Provides cryptographic functions including AES encryption.

You can install these dependencies using pip:

```sh
pip install Pillow pycryptodome
```

## Usage

The GUI prompts users for a password and allows them to select images for encryption/decryption.

### Encrypting an Image

1. Open the application.
2. Enter your desired password in the "Password" field.
3. Click on "Encrypt".
4. Select the image file you want to encrypt from the file dialog box that appears.
5. The encrypted file will be saved with a `.enc` extension.

### Decrypting an Image

1. Open the application.
2. Enter your desired password in the "Password" field.
3. Click on "Decrypt".
4. Select the encrypted image file (`.enc`) you want to decrypt from the file dialog box that appears.
5. The decrypted image will be saved with a `.png` extension.

## Advanced Features

- **Multiple File Encryption**: You can encrypt multiple images by repeating the encryption process for each file.
- **Custom Password Strength**: Choose strong passwords by combining uppercase, lowercase, numbers, and special characters.
- **Password Reset Functionality**: If you forget your password, use the built-in reset functionality to generate a new one.

## Contributing

If you spot any bugs, have suggestions for improvements, or want to contribute additional features, please follow these steps:

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
    ```sh
    git clone https://github.com/tanm-sys/SecureImageTool.git
    ```
3. **Create a branch** for your feature or bug fix:
    ```sh
    cd SecureImageTool
    git checkout -b name-of-your-bugfix-or-feature
    ```
4. **Commit** your changes and push to the remote repository.
5. **Submit a pull request**.

Ensure that your code adheres to PEP 8 style guidelines, and include appropriate documentation and tests if applicable.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

---
