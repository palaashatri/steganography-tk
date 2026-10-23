"""Steganography operations package."""

from .core import (
    MAGIC, VERSION,
    FLAG_ENCRYPTED, FLAG_PRNG, FLAG_LSB_MATCH,
    FLAG_PAYLOAD_IMAGE, FLAG_PAYLOAD_TEXT, FLAG_PAYLOAD_MP3,
    FLAG_COMPRESSED, FLAG_META,
    AUDIO_EXT_LIST, VIDEO_EXT_LIST,
    AUDIO_EXTS, VIDEO_EXTS, MP4_CONTAINER_EXTS, TAGGED_AUDIO_EXTS, FFMPEG_VIDEO_EXTS,
    DEFAULT_SALT_LEN, DEFAULT_NONCE_LEN,
    PBKDF2_ITERATIONS, KEY_LEN,
    StegoHeader,
    parse_header, derive_key,
    bytes_to_bits, bits_to_bytes,
    flatten_channels, rebuild_image,
    embed_bits, embed_bits_prng,
    extract_bits, extract_bits_prng,
    max_payload_bytes, make_rng,
    build_aad, apply_metadata, extract_metadata, check_expiration,
    estimate_stego_payload_size,
    build_stego_payload, parse_stego_payload,
)

from .image import (
    load_image,
    embed_stego_data_in_image, extract_stego_data_from_image,
    image_capacity_bytes,
    embed_data_in_video_frame, extract_data_from_video_frame,
    read_payload,
)

from .audio import (
    load_mp3, load_mp4,
    embed_data_in_mp3, extract_data_from_mp3,
    embed_data_in_mp4, extract_data_from_mp4,
    embed_data_in_audio, extract_data_from_audio,
)

from .video import (
    embed_data_in_video, extract_data_from_video,
)

from .pdf import (
    embed_data_in_pdf, extract_data_from_pdf,
)

from .utils import (
    generate_qr_code, create_portable_decoder, create_windows_file_association,
)

__all__ = [
    # Core constants
    'MAGIC', 'VERSION',
    'FLAG_ENCRYPTED', 'FLAG_PRNG', 'FLAG_LSB_MATCH',
    'FLAG_PAYLOAD_IMAGE', 'FLAG_PAYLOAD_TEXT', 'FLAG_PAYLOAD_MP3',
    'FLAG_COMPRESSED', 'FLAG_META',
    'AUDIO_EXT_LIST', 'VIDEO_EXT_LIST',
    'AUDIO_EXTS', 'VIDEO_EXTS', 'MP4_CONTAINER_EXTS', 'TAGGED_AUDIO_EXTS', 'FFMPEG_VIDEO_EXTS',
    'DEFAULT_SALT_LEN', 'DEFAULT_NONCE_LEN',
    'PBKDF2_ITERATIONS', 'KEY_LEN',
    # Core classes
    'StegoHeader',
    # Core functions
    'parse_header', 'derive_key',
    'bytes_to_bits', 'bits_to_bytes',
    'flatten_channels', 'rebuild_image',
    'embed_bits', 'embed_bits_prng',
    'extract_bits', 'extract_bits_prng',
    'max_payload_bytes', 'make_rng',
    'build_aad', 'apply_metadata', 'extract_metadata', 'check_expiration',
    'estimate_stego_payload_size',
    'build_stego_payload', 'parse_stego_payload',
    # Image functions
    'load_image',
    'embed_stego_data_in_image', 'extract_stego_data_from_image',
    'image_capacity_bytes',
    'embed_data_in_video_frame', 'extract_data_from_video_frame',
    'read_payload',
    # Audio functions
    'load_mp3', 'load_mp4',
    'embed_data_in_mp3', 'extract_data_from_mp3',
    'embed_data_in_mp4', 'extract_data_from_mp4',
    'embed_data_in_audio', 'extract_data_from_audio',
    # Video functions
    'embed_data_in_video', 'extract_data_from_video',
    # PDF functions
    'embed_data_in_pdf', 'extract_data_from_pdf',
    # Utility functions
    'generate_qr_code', 'create_portable_decoder', 'create_windows_file_association',
]
