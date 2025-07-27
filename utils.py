import os
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def ensure_directories_exist(directories):
    """Ensure that required directories exist."""
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logging.debug(f"Ensured directory exists: {directory}")

def get_file_extension(filename):
    """Get the file extension from a filename."""
    if '.' in filename:
        return filename.rsplit('.', 1)[1].lower()
    return ''

def format_file_size(size_bytes):
    """Format file size from bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"

def is_video_file(filename):
    """Check if a file is a video based on its extension."""
    video_extensions = {'mp4', 'avi', 'mov', 'mkv', 'webm', 'flv', 'wmv'}
    ext = get_file_extension(filename)
    return ext in video_extensions

def validate_files(cover_file, secret_file, allowed_extensions):
    """Validate uploaded files."""
    errors = []
    
    # Check if files are provided
    if not cover_file or cover_file.filename == '':
        errors.append("Cover file is required")
    
    if not secret_file or secret_file.filename == '':
        errors.append("Secret file is required")
    
    # Check file extensions
    if cover_file and cover_file.filename != '':
        if get_file_extension(cover_file.filename) not in allowed_extensions:
            errors.append(f"Cover file format not supported. Allowed formats: {', '.join(allowed_extensions)}")
    
    if secret_file and secret_file.filename != '':
        if get_file_extension(secret_file.filename) not in allowed_extensions:
            errors.append(f"Secret file format not supported. Allowed formats: {', '.join(allowed_extensions)}")
    
    return errors