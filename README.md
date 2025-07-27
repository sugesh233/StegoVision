# StegoVision 🔐🎞️
**Video Steganography Web Application using Flask**

StegoVision is a Flask-based web application that enables users to securely hide and extract data within video files using steganography. It supports selective frame encoding, layered compression, and symmetric encryption using user-supplied or auto-generated keys.

---

## 🚀 Features

- 🔐 Embed secret files inside cover videos
- 🔓 Extract hidden data from stego videos
- 🔑 Custom or random encryption key support
- 💾 Compression of secret data for efficient embedding
- 🧠 Dual mode steganography (simple & selective frame)
- 🌐 Web interface for uploads, downloads, and encryption key management

---

## 📁 Project Structure

```

StegoVision/
│
├── main.py                 # Flask application entry point
├── steganography.py        # Core embedding and extraction logic
├── utils.py                # Utility functions (file handling, validation)
├── templates/              # HTML templates (Jinja2)
│   └── index.html
│   └── download.html
├── static/                 # CSS and JavaScript assets
│   └── css/custom.css
├── uploads/                # Temp folder for uploaded files
├── outputs/                # Folder for embedded or extracted outputs
├── .gitignore              # Files to ignore in version control
├── LICENSE                 # MIT License
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation

````

---

## ⚙️ Requirements

- Python 3.7+
- pip (Python package manager)

Dependencies:
- Flask
- Werkzeug
- NumPy
- OpenCV-Python

---

## 🛠️ Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/sugesh233/StegoVision.git
cd StegoVision
````

### 2. Create and activate a virtual environment

```bash
python -m venv venv
venv\Scripts\activate  # Windows
# OR
source venv/bin/activate  # macOS/Linux
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Application

```bash
python main.py
```

Open your browser and navigate to:

```
http://127.0.0.1:5000
```

---

## 🔒 Embedding Workflow

1. Upload a **cover video** (e.g., `.mp4`, `.avi`)
2. Upload a **secret file** (any file type)
3. Enter a custom encryption key (or leave it blank to auto-generate)
4. Click **Encrypt** — download the stego file
5. Save the encryption key to use later for decryption

---

## 🔓 Extraction Workflow

1. Upload the **stego video**
2. Enter the correct encryption key
3. Click **Decrypt**
4. Download the recovered secret file

---

## 🛡️ License

This project is licensed under the MIT License.
See [`LICENSE`](./LICENSE) for more information.

---

## 👨‍💻 Author

**Sugesh**
[GitHub Profile](https://github.com/sugesh233)

