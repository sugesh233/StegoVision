import base64
import secrets
import logging
import numpy as np
import os
import zlib
import struct
import math
import bz2
import gzip
import lzma
import io
from hashlib import sha256

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TextFileSteganography:
    """Simple file-based steganography implementation."""
    
    def __init__(self, key=None):
        """Initialize with optional encryption key."""
        self.key = key or secrets.token_hex(16)
    
    def embed(self, cover_file_path, secret_file_path, output_file_path):
        """
        Embed secret file contents into a cover file.
        
        Args:
            cover_file_path: Path to the cover file (any file)
            secret_file_path: Path to the secret file (any file)
            output_file_path: Path to save the stego file
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Read cover file as binary
            with open(cover_file_path, 'rb') as f:
                cover_data = f.read()
            
            # Read secret file as binary
            with open(secret_file_path, 'rb') as f:
                secret_data = f.read()
            
            # Compress the secret data before encoding
            compressed_secret = zlib.compress(secret_data, level=9)
            
            # Encode compressed secret data with base64
            encoded_secret = base64.b64encode(compressed_secret)
            
            # Create a separator that's unlikely to appear naturally
            separator = b'|STEG_SEP_' + self.key.encode() + b'|'
            
            # Combine cover and secret data
            stego_data = cover_data + separator + encoded_secret
            
            # Write to output file
            with open(output_file_path, 'wb') as f:
                f.write(stego_data)
            
            original_size = len(secret_data)
            final_size = len(compressed_secret)
            compression_ratio = original_size / final_size if final_size > 0 else 0
            
            return True, f"File successfully embedded. Compression ratio: {compression_ratio:.2f}x"
            
        except Exception as e:
            logging.error(f"Error during embedding: {str(e)}")
            return False, f"Error during embedding: {str(e)}"
    
    def extract(self, stego_file_path, output_file_path):
        """
        Extract hidden data from a stego file.
        
        Args:
            stego_file_path: Path to the stego file
            output_file_path: Path to save the extracted secret file
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Read stego file
            with open(stego_file_path, 'rb') as f:
                stego_data = f.read()
            
            # Create the separator pattern
            separator = b'|STEG_SEP_' + self.key.encode() + b'|'
            
            # Find the separator
            separator_pos = stego_data.find(separator)
            
            if separator_pos == -1:
                return False, "No hidden data found or incorrect key."
            
            # Extract the hidden data
            hidden_data = stego_data[separator_pos + len(separator):]
            
            # Decode from base64 and decompress
            try:
                decoded_data = base64.b64decode(hidden_data)
                decompressed_data = zlib.decompress(decoded_data)
            except Exception as e:
                return False, f"Data extraction failed: {str(e)}. The file may be corrupted or not contain valid hidden data."
            
            # Write extracted data
            with open(output_file_path, 'wb') as f:
                f.write(decompressed_data)
            
            return True, "Hidden data successfully extracted."
            
        except Exception as e:
            logging.error(f"Error during extraction: {str(e)}")
            return False, f"Error during extraction: {str(e)}"

class SelectiveFrameStegano:
    """Implements steganography by embedding data only in selected frames with extreme compression."""
    
    def __init__(self, key=None, frame_interval=5, bits_per_byte=3):
        """
        Initialize with optional encryption key and frame selection interval.
        
        Args:
            key: Encryption key string (optional)
            frame_interval: Only process one frame every 'frame_interval' frames
            bits_per_byte: Number of bits to use per byte for LSB encoding (1-8)
        """
        self.key = key or secrets.token_hex(16)
        self.frame_interval = frame_interval
        self.bits_per_byte = min(max(bits_per_byte, 1), 8)  # Ensure between 1-8
        self.chunk_size = 1024  # Size of each data chunk to embed in bytes
    
    def _optimize_bit_distribution(self, data_size, frame_count, frame_size):
        """Calculate optimal bit distribution to minimize visual impact."""
        total_bytes_available = frame_count * frame_size
        if total_bytes_available * 0.125 < data_size:
            # We need higher bit density
            return min(self.bits_per_byte, 8)
        else:
            # We can afford lower bit density
            return 1  # Just use 1 bit per byte for minimal visual impact
    
    def _split_data_into_chunks(self, data, chunk_size):
        """Split binary data into fixed-size chunks."""
        return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    def _ultra_compress(self, data):
        """
        Apply a multi-stage compression to achieve maximum compression.
        
        This tries different algorithms and combinations to achieve the best results.
        """
        # Start with dictionary-based compression
        compressed1 = zlib.compress(data, level=9)
        compressed2 = bz2.compress(data, compresslevel=9)
        compressed3 = lzma.compress(data, preset=9 | lzma.PRESET_EXTREME)
        
        # Choose the best initial compression
        best_compression = min([compressed1, compressed2, compressed3], key=len)
        
        # Apply a second round of compression if beneficial
        secondary_compression = zlib.compress(best_compression, level=9)
        
        return secondary_compression if len(secondary_compression) < len(best_compression) else best_compression
    
    def _ultra_decompress(self, compressed_data):
        """
        Attempt to decompress data that was compressed with _ultra_compress.
        
        This tries different algorithms in sequence until one works.
        """
        # Try the algorithms in reverse order
        try:
            # First check if it's a secondary compression
            try:
                decompressed = zlib.decompress(compressed_data)
                
                # Now try all primary decompression methods
                try:
                    return zlib.decompress(decompressed)
                except:
                    try:
                        return bz2.decompress(decompressed)
                    except:
                        try:
                            return lzma.decompress(decompressed)
                        except:
                            return decompressed  # It might be already decompressed
                            
            except:
                # Not a secondary compression, try primary methods
                try:
                    return zlib.decompress(compressed_data)
                except:
                    try:
                        return bz2.decompress(compressed_data)
                    except:
                        return lzma.decompress(compressed_data)
        except Exception as e:
            logging.error(f"All decompression methods failed: {str(e)}")
            raise ValueError("Failed to decompress data. The data may be corrupted.")
    
    def _encode_data_in_bytes(self, cover_bytes, secret_bytes, bits_per_byte=None):
        """
        Encode secret bytes into the least significant bits of cover bytes.
        
        This uses a configurable LSB (Least Significant Bit) technique.
        
        Args:
            cover_bytes: The original bytes to hide data in
            secret_bytes: The data to hide
            bits_per_byte: Number of bits to use per byte (overrides self.bits_per_byte)
        """
        if not secret_bytes:
            return cover_bytes
            
        # Use specified or default bits_per_byte
        bits = bits_per_byte or self.bits_per_byte
        
        # Calculate capacity based on the number of bits we're using
        capacity = len(cover_bytes) * bits // 8
        if len(secret_bytes) > capacity:
            secret_bytes = secret_bytes[:capacity]
        
        # Make a copy of the cover bytes
        result = bytearray(cover_bytes)
        
        # Prepare a bit array of the secret data
        bit_array = []
        for b in secret_bytes:
            for bit_pos in range(8):
                bit_array.append((b >> bit_pos) & 1)
        
        # Embed the bit array into the cover bytes
        for i, bit in enumerate(bit_array):
            if i >= len(cover_bytes) * bits:
                break
                
            byte_pos = i // bits
            bit_pos = i % bits
            
            # Clear the LSB (according to which bit we're replacing) and set it to the secret bit
            mask = ~(1 << bit_pos)
            result[byte_pos] = (result[byte_pos] & mask) | (bit << bit_pos)
            
        return bytes(result)
    
    def _decode_data_from_bytes(self, stego_bytes, output_size, bits_per_byte=None):
        """
        Decode secret data from the LSBs of stego bytes.
        
        Args:
            stego_bytes: The bytes containing hidden data
            output_size: The size of the output data in bytes
            bits_per_byte: Number of bits used per byte (overrides self.bits_per_byte)
        """
        if not stego_bytes or output_size <= 0:
            return b''
        
        # Use specified or default bits_per_byte
        bits = bits_per_byte or self.bits_per_byte
        
        # Calculate how many bytes we can extract
        capacity = len(stego_bytes) * bits // 8
        output_size = min(output_size, capacity)
        
        # Create a bit array from the stego bytes
        bit_array = []
        for byte_pos in range(len(stego_bytes)):
            for bit_pos in range(bits):
                if byte_pos * bits + bit_pos < len(stego_bytes) * bits:
                    bit_val = (stego_bytes[byte_pos] >> bit_pos) & 1
                    bit_array.append(bit_val)
        
        # Convert the bit array back to bytes
        result = bytearray(output_size)
        for i in range(output_size):
            if i * 8 + 7 < len(bit_array):
                byte_val = 0
                for bit_pos in range(8):
                    if i * 8 + bit_pos < len(bit_array):
                        byte_val |= bit_array[i * 8 + bit_pos] << bit_pos
                result[i] = byte_val
        
        return bytes(result)
    
    def embed_video(self, cover_path, secret_path, output_path):
        """
        Embed secret video data within selected frames of a cover video.
        
        This implements selective frame encoding to reduce file size impact.
        """
        try:
            # Get the raw data from both files
            with open(cover_path, 'rb') as f:
                cover_data = f.read()
                
            with open(secret_path, 'rb') as f:
                secret_data = f.read()
                
            # Create a checksum of the original data
            original_checksum = sha256(secret_data).digest()
            
            # Apply ultra-compression to the secret data
            compressed_data = self._ultra_compress(secret_data)
            
            logging.info(f"Original size: {len(secret_data)} bytes, Compressed: {len(compressed_data)} bytes, Ratio: {len(secret_data)/len(compressed_data):.2f}x")
            
            # Calculate metadata: compressed size, original size, checksum
            metadata = struct.pack("<QQ", len(compressed_data), len(secret_data)) + original_checksum
            
            # Prepare the data to embed (metadata + compressed data)
            data_to_embed = metadata + compressed_data
            data_size = len(data_to_embed)
            
            # Add key as a signature for verification during extraction
            key_signature = self.key.encode()
            data_to_embed = key_signature + struct.pack("<I", len(key_signature)) + data_to_embed
            
            # Calculations for selective embedding
            # We'll assume 10% of the file is header, 90% is frame data
            header_size = min(int(len(cover_data) * 0.1), 1024 * 1024)  # Up to 1MB
            frame_data = cover_data[header_size:]
            
            # Preserve the header exactly as is
            output_data = bytearray(cover_data[:header_size])
            
            # Estimate frame size and apply more aggressive frame skipping for larger files
            frame_size_estimate = 1024 * 10  # Assume 10KB per frame on average
            
            # For very large secret files, increase frame interval dynamically
            if len(compressed_data) > 1024 * 1024:  # > 1MB
                dynamic_interval = max(self.frame_interval, int(len(compressed_data) / (1024 * 1024)) + 1)
                logging.info(f"Using dynamic frame interval of {dynamic_interval} (secret size: {len(compressed_data)/1024/1024:.2f}MB)")
            else:
                dynamic_interval = self.frame_interval
            
            # Split the frame data into "frames" (rough approximation)
            frame_chunks = [frame_data[i:i+frame_size_estimate] for i in range(0, len(frame_data), frame_size_estimate)]
            
            # Count usable frames (every Nth frame)
            usable_frames = len(frame_chunks) // dynamic_interval
            
            # Calculate optimal bit distribution
            optimal_bits = self._optimize_bit_distribution(
                len(data_to_embed), 
                usable_frames, 
                frame_size_estimate
            )
            
            logging.info(f"Using {optimal_bits} bits per byte for embedding")
            
            # Split the secret data into chunks that will fit in the selected frames
            bytes_per_frame = frame_size_estimate * optimal_bits // 8  # Capacity based on bits used
            secret_chunks = self._split_data_into_chunks(data_to_embed, bytes_per_frame)
            
            # Track how many secret chunks we've embedded
            embedded_chunks = 0
            
            # Process each frame, only embedding in every Nth frame
            for i, frame in enumerate(frame_chunks):
                if i % dynamic_interval == 0 and embedded_chunks < len(secret_chunks):
                    # This is a selected frame - embed data
                    modified_frame = self._encode_data_in_bytes(
                        frame, 
                        secret_chunks[embedded_chunks],
                        optimal_bits
                    )
                    output_data.extend(modified_frame)
                    embedded_chunks += 1
                else:
                    # Not a selected frame - leave unchanged
                    output_data.extend(frame)
            
            # If we couldn't embed all chunks, it's a failure
            if embedded_chunks < len(secret_chunks):
                return False, "Cover video too small to hide the secret data"
            
            # Write the output file
            with open(output_path, 'wb') as f:
                f.write(output_data)
            
            # Calculate the compression stats
            original_size = len(secret_data)
            embedded_size = len(data_to_embed)
            final_size = len(output_data) - len(cover_data)
            
            # Adjust reported final size based on negative or positive values
            if final_size < 0:
                size_impact = f"Reduced by {abs(final_size)} bytes"
            else:
                size_impact = f"Added {final_size} bytes"
                
            compression_info = (
                f"Original: {original_size:,} bytes, "
                f"Compressed: {embedded_size:,} bytes, "
                f"Impact: {size_impact}, "
                f"Compression ratio: {original_size/embedded_size:.2f}x"
            )
            
            logging.info(f"Selective frame encoding complete. {compression_info}")
            return True, f"Video successfully embedded using selective frame encoding. {compression_info}"
            
        except Exception as e:
            logging.error(f"Error during selective frame encoding: {str(e)}")
            return False, f"Error during embedding: {str(e)}"
    
    def extract_video(self, stego_path, output_path):
        """Extract hidden data from selected frames of a stego video."""
        try:
            # Read the stego file
            with open(stego_path, 'rb') as f:
                stego_data = f.read()
            
            # Skip the header (approximate)
            header_size = min(int(len(stego_data) * 0.1), 1024 * 1024)
            frame_data = stego_data[header_size:]
            
            # Estimate frame size 
            frame_size_estimate = 1024 * 10  # Same as embedding
            
            # Determine if this is a large file that would have used dynamic interval
            dynamic_interval = self.frame_interval
            
            # Split the frame data into "frames"
            frame_chunks = [frame_data[i:i+frame_size_estimate] for i in range(0, len(frame_data), frame_size_estimate)]
            
            # Initialize an array to collect the embedded data
            extracted_data = bytearray()
            
            # Process selected frames with multiple bit depth attempts
            for bits_per_byte in [self.bits_per_byte, 1, 2, 3, 4]:
                extracted_data = bytearray()
                
                for i, frame in enumerate(frame_chunks):
                    if i % dynamic_interval == 0:
                        # Calculate how many bytes we might expect in this frame
                        capacity = len(frame) * bits_per_byte // 8
                        
                        # Extract data from this frame
                        frame_data = self._decode_data_from_bytes(frame, capacity, bits_per_byte)
                        extracted_data.extend(frame_data)
                
                # Look for the key signature at the beginning
                key_signature = self.key.encode()
                
                if extracted_data.startswith(key_signature):
                    logging.info(f"Found valid key signature with {bits_per_byte} bits per byte")
                    break
            
            # If we couldn't find a valid signature, try falling back to simpler method
            if not extracted_data.startswith(key_signature):
                # Try different intervals
                for alt_interval in [2, 3, 4, 5, 10]:
                    if alt_interval == dynamic_interval:
                        continue
                        
                    logging.info(f"Trying alternative frame interval {alt_interval}")
                    extracted_data = bytearray()
                    
                    for i, frame in enumerate(frame_chunks):
                        if i % alt_interval == 0:
                            # Try a fixed bit depth of 1 for maximum compatibility
                            capacity = len(frame) * 1 // 8
                            frame_data = self._decode_data_from_bytes(frame, capacity, 1)
                            extracted_data.extend(frame_data)
                    
                    if extracted_data.startswith(key_signature):
                        logging.info(f"Found valid key signature with interval {alt_interval}")
                        break
            
            # If still no valid signature, it's an error
            if not extracted_data.startswith(key_signature):
                return False, "Could not find key signature. Invalid key or no hidden data."
            
            # Skip the key signature and get its length
            pos = len(key_signature)
            key_len = struct.unpack("<I", extracted_data[pos:pos+4])[0]
            pos += 4
            
            if key_len != len(key_signature):
                return False, "Key length mismatch. Invalid key or corrupted data."
            
            # Extract the metadata (compressed size, original size, checksum)
            compressed_size, original_size = struct.unpack("<QQ", extracted_data[pos:pos+16])
            pos += 16
            original_checksum = extracted_data[pos:pos+32]
            pos += 32
            
            # Get the compressed data
            compressed_data = extracted_data[pos:pos+compressed_size]
            
            # Decompress the data
            try:
                original_data = self._ultra_decompress(compressed_data)
                
                if len(original_data) != original_size:
                    return False, f"Size mismatch after decompression. Expected {original_size} bytes, got {len(original_data)} bytes."
                
                # Verify the checksum
                if sha256(original_data).digest() != original_checksum:
                    return False, "Checksum mismatch. Data may be corrupted."
                
                # Write the extracted data
                with open(output_path, 'wb') as f:
                    f.write(original_data)
                
                return True, "Hidden video successfully extracted and verified."
                
            except Exception as e:
                return False, f"Error during decompression: {str(e)}"
            
        except Exception as e:
            logging.error(f"Error during selective frame extraction: {str(e)}")
            return False, f"Error during extraction: {str(e)}"

class VideoSteganography:
    """
    A simplified version of the video steganography class 
    that doesn't rely on OpenCV or PyWavelets, for better compatibility.
    """
    
    def __init__(self, key=None, frame_interval=5):
        """Initialize with optional encryption key."""
        self.key = key or secrets.token_hex(16)
        self.frame_interval = frame_interval
    
    def embed_video(self, cover_path, secret_path, output_path):
        """Embed a secret video within a cover video using selective frame encoding"""
        try:
            # Use the new selective frame encoding method
            steg = SelectiveFrameStegano(key=self.key, frame_interval=self.frame_interval)
            success, message = steg.embed_video(cover_path, secret_path, output_path)
            
            if not success:
                # Fall back to the simpler method if selective encoding fails
                logging.warning("Selective frame encoding failed, falling back to simpler method")
                simple_steg = TextFileSteganography(key=self.key)
                success, message = simple_steg.embed(cover_path, secret_path, output_path)
            
            logging.info(f"Video embedding complete. Output saved to {output_path}")
            return success
            
        except Exception as e:
            logging.error(f"Error during video embedding: {str(e)}")
            return False

    def extract_video(self, stego_path, output_path):
        """Extract a hidden video from a stego video"""
        try:
            # Try selective frame extraction first
            steg = SelectiveFrameStegano(key=self.key, frame_interval=self.frame_interval)
            success, message = steg.extract_video(stego_path, output_path)
            
            if not success:
                # Fall back to the simpler method if selective extraction fails
                logging.warning("Selective frame extraction failed, falling back to simpler method")
                simple_steg = TextFileSteganography(key=self.key)
                success, message = simple_steg.extract(stego_path, output_path)
            
            logging.info(f"Video extraction complete. Output saved to {output_path}")
            return success
            
        except Exception as e:
            logging.error(f"Error during video extraction: {str(e)}")
            return False