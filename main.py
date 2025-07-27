import os
import logging
import time
import secrets
from flask import Flask, render_template, request, send_from_directory, redirect, url_for, flash
from werkzeug.utils import secure_filename
from steganography import TextFileSteganography, VideoSteganography
from utils import ensure_directories_exist, get_file_extension

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key_for_development")

# Create upload folders if they don't exist
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv'}

ensure_directories_exist([UPLOAD_FOLDER, OUTPUT_FOLDER])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload size

def allowed_file(filename):
    """Check if the file extension is allowed"""
    if not filename:
        return False
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Handle file embedding (hiding a secret file in a cover file)"""
    logging.debug("Received form submission to /encrypt")
    logging.debug(f"Form data: {request.form}")
    logging.debug(f"Files keys: {list(request.files.keys())}")
    
    # Check if both files are present
    if 'cover_file' not in request.files or 'secret_file' not in request.files:
        logging.error("Missing required files in request")
        flash('Both cover and secret files are required')
        return redirect(url_for('index'))
    
    cover_file = request.files['cover_file']
    secret_file = request.files['secret_file']
    
    logging.debug(f"Cover file name: {cover_file.filename}, Content type: {cover_file.content_type}")
    logging.debug(f"Secret file name: {secret_file.filename}, Content type: {secret_file.content_type}")
    
    # Check if file selections are valid
    if not cover_file.filename or not secret_file.filename:
        logging.error(f"Empty filenames detected: cover={cover_file.filename}, secret={secret_file.filename}")
        flash('Both cover and secret files are required')
        return redirect(url_for('index'))
    
    # Check file extensions
    if not (allowed_file(cover_file.filename) and allowed_file(secret_file.filename)):
        flash('Invalid file format. Only videos in mp4, avi, mov, or mkv format are allowed')
        return redirect(url_for('index'))
    
    # Get encryption key (optional)
    encryption_key = request.form.get('encryption_key', '')
    if not encryption_key:
        encryption_key = secrets.token_hex(16)  # Generate random key if not provided
    
    # Create unique filenames
    timestamp = int(time.time())
    cover_filename = f"{timestamp}_cover_{secure_filename(cover_file.filename)}"
    secret_filename = f"{timestamp}_secret_{secure_filename(secret_file.filename)}"
    output_filename = f"{timestamp}_embedded.{get_file_extension(cover_file.filename)}"
    
    # Save the uploaded files
    cover_path = os.path.join(app.config['UPLOAD_FOLDER'], cover_filename)
    secret_path = os.path.join(app.config['UPLOAD_FOLDER'], secret_filename)
    output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
    
    cover_file.save(cover_path)
    secret_file.save(secret_path)
    
    try:
        # Determine which steganography method to use
        # For simplicity, we'll use TextFileSteganography for videos less than 10MB
        # and VideoSteganography for larger files or where both are videos
        file_size = os.path.getsize(cover_path)
        
        if file_size < 10 * 1024 * 1024:  # Less than 10MB
            # Use simple file-based steganography
            steg = TextFileSteganography(key=encryption_key)
            success, message = steg.embed(cover_path, secret_path, output_path)
        else:
            # Use alternative video steganography
            steg = VideoSteganography(key=encryption_key)
            success = steg.embed_video(cover_path, secret_path, output_path)
            message = "Video processing complete" if success else "Error processing video"
    
        if success:
            flash('Embedding completed successfully. Your encryption key is: ' + encryption_key)
            return render_template('download.html', filename=output_filename, encryption_key=encryption_key)
        else:
            flash(f'Error during embedding: {message}')
            return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Error during embedding process: {str(e)}")
        flash(f'An error occurred during the embedding process: {str(e)}')
        return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Handle file extraction (recovering a hidden file from a stego file)"""
    logging.debug("Received form submission to /decrypt")
    logging.debug(f"Form data: {request.form}")
    logging.debug(f"Files keys: {list(request.files.keys())}")
    
    # Check if stego file is present
    if 'stego_file' not in request.files:
        flash('Stego file with hidden data is required')
        return redirect(url_for('index'))
    
    stego_file = request.files['stego_file']
    
    # Check if file selection is valid
    if not stego_file.filename:
        flash('Stego file with hidden data is required')
        return redirect(url_for('index'))
    
    # Check file extension
    if not allowed_file(stego_file.filename):
        flash('Invalid file format. Only videos in mp4, avi, mov, or mkv format are allowed')
        return redirect(url_for('index'))
    
    # Get decryption key
    decryption_key = request.form.get('decryption_key', '')
    if not decryption_key:
        flash('Decryption key is required')
        return redirect(url_for('index'))

    # Create unique filenames
    timestamp = int(time.time())
    stego_filename = f"{timestamp}_stego_{secure_filename(stego_file.filename)}"
    output_filename = f"{timestamp}_extracted.{get_file_extension(stego_file.filename)}"

    # Save the uploaded file
    stego_path = os.path.join(app.config['UPLOAD_FOLDER'], stego_filename)
    output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
    
    stego_file.save(stego_path)
    
    try:
        # Determine which extraction method to use based on file size
        file_size = os.path.getsize(stego_path)
        
        if file_size < 10 * 1024 * 1024:  # Less than 10MB
            # Use simple file-based steganography extraction
            steg = TextFileSteganography(key=decryption_key)
            success, message = steg.extract(stego_path, output_path)
        else:
            # Use alternative video steganography extraction
            steg = VideoSteganography(key=decryption_key)
            success = steg.extract_video(stego_path, output_path)
            message = "Video extraction complete" if success else "Error extracting from video"
        
        if success:
            flash('Extraction completed successfully')
            return render_template('download.html', filename=output_filename)
        else:
            flash(f'Error during extraction: {message}')
            return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Error during extraction process: {str(e)}")
        flash(f'An error occurred during the extraction process: {str(e)}')
        return redirect(url_for('index'))

@app.route('/downloads/<filename>')
def download_file(filename):
    """Render the download page"""
    key = request.args.get('key', None)
    return render_template('download.html', filename=filename, encryption_key=key)

@app.route('/get_file/<filename>')
def get_file(filename):
    """Serve the file for download"""
    return send_from_directory(app.config['OUTPUT_FOLDER'], filename, as_attachment=True)

@app.route('/cleanup', methods=['POST'])
def cleanup():
    """Cleanup temporary files (optional, triggered by JS)"""
    # This could be implemented to remove temp files after download
    return {'status': 'success'}

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)