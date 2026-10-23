"""Command-line LSB steganography with optional AES-GCM protection.

CLI wrapper around the stego package.
"""

from __future__ import annotations

import argparse
import logging
from typing import Sequence

# Import all steganography operations from stego package
from stego import (
    # Core operations
    load_image, read_payload, build_stego_payload, parse_stego_payload,
    # Image operations
    embed_stego_data_in_image, extract_stego_data_from_image,
    embed_data_in_gif, extract_data_from_gif,
    embed_data_in_video_frame, extract_data_from_video_frame,
    # Audio operations
    embed_data_in_audio, extract_data_from_audio,
    # Video operations
    embed_data_in_video, extract_data_from_video,
    # PDF operations
    embed_data_in_pdf, extract_data_from_pdf,
    # Utilities
    generate_qr_code, create_portable_decoder, create_windows_file_association,
)


def encode_image(args: argparse.Namespace) -> None:
    """Encode data into image using LSB steganography."""
    image = load_image(args.image)
    payload = read_payload(args.message, args.in_file)
    flags = 0
    stego_data, _, _, _ = build_stego_payload(
        payload, flags, args.password, args.compress, args.comment, args.expires
    )
    stego_image = embed_stego_data_in_image(image, stego_data, args.method, args.prng_key)
    stego_image.save(args.out)
    logging.info("Wrote stego image to %s", args.out)


def decode_image(args: argparse.Namespace) -> None:
    """Decode data from image using LSB steganography."""
    image = load_image(args.image)
    stego_data = extract_stego_data_from_image(image, args.method, args.prng_key)
    _, plaintext, _ = parse_stego_payload(stego_data, args.password)

    if args.out:
        with open(args.out, "wb") as f:
            f.write(plaintext)
        logging.info("Wrote decoded payload to %s", args.out)
    else:
        try:
            print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            print(plaintext.decode("utf-8", errors="replace"))


def encode_audio(args: argparse.Namespace) -> None:
    """Encode data into audio file."""
    embed_data_in_audio(
        args.audio, args.out,
        password=args.password,
        message=getattr(args, 'message', None),
        in_file=getattr(args, 'in_file', None),
        image_path=getattr(args, 'image', None),
        compress=getattr(args, 'compress', False),
        comment=getattr(args, 'comment', None),
        expires=getattr(args, 'expires', None),
    )


def decode_audio(args: argparse.Namespace) -> None:
    """Decode data from audio file."""
    extract_data_from_audio(args.audio, args.out, password=args.password)


def encode_video(args: argparse.Namespace) -> None:
    """Encode data into video file."""
    embed_data_in_video(
        args.video, args.out,
        password=args.password,
        message=getattr(args, 'message', None),
        in_file=getattr(args, 'in_file', None),
        image_path=getattr(args, 'image', None),
        mp3_path=getattr(args, 'mp3', None),
        compress=getattr(args, 'compress', False),
        comment=getattr(args, 'comment', None),
        expires=getattr(args, 'expires', None),
    )


def decode_video(args: argparse.Namespace) -> None:
    """Decode data from video file."""
    extract_data_from_video(args.video, args.out, password=args.password)


def encode_pdf(args: argparse.Namespace) -> None:
    """Encode data into PDF file."""
    embed_data_in_pdf(
        args.pdf, args.out,
        password=args.password,
        message=getattr(args, 'message', None),
        in_file=getattr(args, 'in_file', None),
        compress=getattr(args, 'compress', False),
        comment=getattr(args, 'comment', None),
        expires=getattr(args, 'expires', None),
    )


def decode_pdf(args: argparse.Namespace) -> None:
    """Decode data from PDF file."""
    extract_data_from_pdf(args.pdf, args.out, password=args.password)


def encode_gif(args: argparse.Namespace) -> None:
    """Encode data into GIF frame."""
    embed_data_in_gif(
        args.gif, args.out, args.frame,
        message=getattr(args, 'message', None),
        in_file=getattr(args, 'in_file', None),
        password=args.password,
        method=getattr(args, 'method', 'lsb'),
        prng_key=getattr(args, 'prng_key', None),
        compress=getattr(args, 'compress', False),
        comment=getattr(args, 'comment', None),
        expires=getattr(args, 'expires', None),
    )


def decode_gif(args: argparse.Namespace) -> None:
    """Decode data from GIF frame."""
    plaintext = extract_data_from_gif(
        args.gif, args.frame,
        password=args.password,
        method=getattr(args, 'method', 'lsb'),
        prng_key=getattr(args, 'prng_key', None),
    )
    with open(args.out, "wb") as f:
        f.write(plaintext)
    logging.info("Wrote decoded payload to %s", args.out)


def encode_video_frame(args: argparse.Namespace) -> None:
    """Encode data into video frame."""
    embed_data_in_video_frame(
        args.video, args.out, args.frame,
        message=getattr(args, 'message', None),
        in_file=getattr(args, 'in_file', None),
        password=args.password,
        method=getattr(args, 'method', 'lsb'),
        prng_key=getattr(args, 'prng_key', None),
        compress=getattr(args, 'compress', False),
        comment=getattr(args, 'comment', None),
        expires=getattr(args, 'expires', None),
    )


def decode_video_frame(args: argparse.Namespace) -> None:
    """Decode data from video frame."""
    plaintext = extract_data_from_video_frame(
        args.video, args.frame,
        password=args.password,
        method=getattr(args, 'method', 'lsb'),
        prng_key=getattr(args, 'prng_key', None),
    )
    with open(args.out, "wb") as f:
        f.write(plaintext)
    logging.info("Wrote decoded payload to %s", args.out)


def generate_qr(args: argparse.Namespace) -> None:
    """Generate QR code."""
    generate_qr_code(args.text, args.out)
    logging.info("Generated QR code: %s", args.out)


def build_portable_decoder(args: argparse.Namespace) -> None:
    """Create portable decoder package."""
    create_portable_decoder(
        args.stego,
        args.out,
        getattr(args, 'method', None),
        getattr(args, 'prng_key', None),
        getattr(args, 'password', None),
        getattr(args, 'frame', None),
    )
    logging.info("Created portable decoder: %s", args.out)


def generate_file_association(args: argparse.Namespace) -> None:
    """Generate Windows file association registry file."""
    create_windows_file_association(args.out, args.app_path, args.python_path)
    logging.info("Generated file association registry: %s", args.out)


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser for CLI."""
    parser = argparse.ArgumentParser(
        prog="stego",
        description="LSB steganography with optional AES-GCM encryption"
    )
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Image encode
    enc_img = subparsers.add_parser("encode", help="Encode data into image")
    enc_img.add_argument("--image", required=True, help="Input image path")
    enc_img.add_argument("--out", required=True, help="Output stego image path")
    enc_img.add_argument("--message", help="Text message to hide")
    enc_img.add_argument("--in-file", help="File to hide")
    enc_img.add_argument("--password", help="Encryption password")
    enc_img.add_argument("--method", default="lsb", choices=["lsb", "lsb-prng", "lsb-match-prng"])
    enc_img.add_argument("--prng-key", help="PRNG key for lsb-prng methods")
    enc_img.add_argument("--compress", action="store_true", help="Compress payload")
    enc_img.add_argument("--comment", help="Metadata comment")
    enc_img.add_argument("--expires", help="Expiration date (ISO format)")
    enc_img.set_defaults(func=encode_image)

    # Image decode
    dec_img = subparsers.add_parser("decode", help="Decode data from image")
    dec_img.add_argument("--image", required=True, help="Stego image path")
    dec_img.add_argument("--out", help="Output file path (prints to stdout if omitted)")
    dec_img.add_argument("--password", help="Decryption password")
    dec_img.add_argument("--method", default="lsb", choices=["lsb", "lsb-prng", "lsb-match-prng"])
    dec_img.add_argument("--prng-key", help="PRNG key")
    dec_img.set_defaults(func=decode_image)

    # Audio encode
    enc_aud = subparsers.add_parser("audio-encode", help="Encode data into audio")
    enc_aud.add_argument("--audio", required=True, help="Input audio path")
    enc_aud.add_argument("--out", required=True, help="Output stego audio path")
    enc_aud.add_argument("--message", help="Text message")
    enc_aud.add_argument("--in-file", help="File to hide")
    enc_aud.add_argument("--image", help="Image to hide (MP3/M4A only)")
    enc_aud.add_argument("--password", help="Encryption password")
    enc_aud.add_argument("--compress", action="store_true")
    enc_aud.add_argument("--comment", help="Metadata comment")
    enc_aud.add_argument("--expires", help="Expiration date")
    enc_aud.set_defaults(func=encode_audio)

    # Audio decode
    dec_aud = subparsers.add_parser("audio-decode", help="Decode data from audio")
    dec_aud.add_argument("--audio", required=True, help="Stego audio path")
    dec_aud.add_argument("--out", required=True, help="Output path")
    dec_aud.add_argument("--password", help="Decryption password")
    dec_aud.set_defaults(func=decode_audio)

    # Video encode
    enc_vid = subparsers.add_parser("video-encode", help="Encode data into video")
    enc_vid.add_argument("--video", required=True, help="Input video path")
    enc_vid.add_argument("--out", required=True, help="Output stego video path")
    enc_vid.add_argument("--message", help="Text message")
    enc_vid.add_argument("--in-file", help="File to hide")
    enc_vid.add_argument("--image", help="Image to hide (MP4/MOV only)")
    enc_vid.add_argument("--mp3", help="MP3 to hide (MP4/MOV only)")
    enc_vid.add_argument("--password", help="Encryption password")
    enc_vid.add_argument("--compress", action="store_true")
    enc_vid.add_argument("--comment", help="Metadata comment")
    enc_vid.add_argument("--expires", help="Expiration date")
    enc_vid.set_defaults(func=encode_video)

    # Video decode
    dec_vid = subparsers.add_parser("video-decode", help="Decode data from video")
    dec_vid.add_argument("--video", required=True, help="Stego video path")
    dec_vid.add_argument("--out", required=True, help="Output path")
    dec_vid.add_argument("--password", help="Decryption password")
    dec_vid.set_defaults(func=decode_video)

    # PDF encode
    enc_pdf = subparsers.add_parser("pdf-encode", help="Encode data into PDF")
    enc_pdf.add_argument("--pdf", required=True, help="Input PDF path")
    enc_pdf.add_argument("--out", required=True, help="Output stego PDF path")
    enc_pdf.add_argument("--message", help="Text message")
    enc_pdf.add_argument("--in-file", help="File to hide")
    enc_pdf.add_argument("--password", help="Encryption password")
    enc_pdf.add_argument("--compress", action="store_true")
    enc_pdf.add_argument("--comment", help="Metadata comment")
    enc_pdf.add_argument("--expires", help="Expiration date")
    enc_pdf.set_defaults(func=encode_pdf)

    # PDF decode
    dec_pdf = subparsers.add_parser("pdf-decode", help="Decode data from PDF")
    dec_pdf.add_argument("--pdf", required=True, help="Stego PDF path")
    dec_pdf.add_argument("--out", required=True, help="Output path")
    dec_pdf.add_argument("--password", help="Decryption password")
    dec_pdf.set_defaults(func=decode_pdf)

    # GIF encode
    enc_gif = subparsers.add_parser("gif-encode", help="Encode data into GIF frame")
    enc_gif.add_argument("--gif", required=True, help="Input GIF path")
    enc_gif.add_argument("--out", required=True, help="Output stego GIF path")
    enc_gif.add_argument("--frame", type=int, required=True, help="Frame index")
    enc_gif.add_argument("--message", help="Text message")
    enc_gif.add_argument("--in-file", help="File to hide")
    enc_gif.add_argument("--password", help="Encryption password")
    enc_gif.add_argument("--method", default="lsb", choices=["lsb", "lsb-prng", "lsb-match-prng"])
    enc_gif.add_argument("--prng-key", help="PRNG key")
    enc_gif.add_argument("--compress", action="store_true")
    enc_gif.add_argument("--comment", help="Metadata comment")
    enc_gif.add_argument("--expires", help="Expiration date")
    enc_gif.set_defaults(func=encode_gif)

    # GIF decode
    dec_gif = subparsers.add_parser("gif-decode", help="Decode data from GIF frame")
    dec_gif.add_argument("--gif", required=True, help="Stego GIF path")
    dec_gif.add_argument("--frame", type=int, required=True, help="Frame index")
    dec_gif.add_argument("--out", required=True, help="Output path")
    dec_gif.add_argument("--password", help="Decryption password")
    dec_gif.add_argument("--method", default="lsb", choices=["lsb", "lsb-prng", "lsb-match-prng"])
    dec_gif.add_argument("--prng-key", help="PRNG key")
    dec_gif.set_defaults(func=decode_gif)

    # Video frame encode
    enc_vf = subparsers.add_parser("video-frame-encode", help="Encode data into video frame")
    enc_vf.add_argument("--video", required=True, help="Input video path")
    enc_vf.add_argument("--out", required=True, help="Output stego video path")
    enc_vf.add_argument("--frame", type=int, required=True, help="Frame index")
    enc_vf.add_argument("--message", help="Text message")
    enc_vf.add_argument("--in-file", help="File to hide")
    enc_vf.add_argument("--password", help="Encryption password")
    enc_vf.add_argument("--method", default="lsb", choices=["lsb", "lsb-prng", "lsb-match-prng"])
    enc_vf.add_argument("--prng-key", help="PRNG key")
    enc_vf.add_argument("--compress", action="store_true")
    enc_vf.add_argument("--comment", help="Metadata comment")
    enc_vf.add_argument("--expires", help="Expiration date")
    enc_vf.set_defaults(func=encode_video_frame)

    # Video frame decode
    dec_vf = subparsers.add_parser("video-frame-decode", help="Decode data from video frame")
    dec_vf.add_argument("--video", required=True, help="Stego video path")
    dec_vf.add_argument("--frame", type=int, required=True, help="Frame index")
    dec_vf.add_argument("--out", required=True, help="Output path")
    dec_vf.add_argument("--password", help="Decryption password")
    dec_vf.add_argument("--method", default="lsb", choices=["lsb", "lsb-prng", "lsb-match-prng"])
    dec_vf.add_argument("--prng-key", help="PRNG key")
    dec_vf.set_defaults(func=decode_video_frame)

    # QR code
    qr = subparsers.add_parser("qr", help="Generate QR code")
    qr.add_argument("--text", required=True, help="Text to encode")
    qr.add_argument("--out", required=True, help="Output image path")
    qr.set_defaults(func=generate_qr)

    # Portable decoder
    decoder = subparsers.add_parser("portable-decoder", help="Create portable decoder")
    decoder.add_argument("--stego", required=True, help="Stego file path")
    decoder.add_argument("--out", required=True, help="Output zip path")
    decoder.add_argument("--method", choices=["lsb", "lsb-prng", "lsb-match-prng"])
    decoder.add_argument("--prng-key")
    decoder.add_argument("--password")
    decoder.add_argument("--frame", type=int, help="Frame index (for GIF/video)")
    decoder.set_defaults(func=build_portable_decoder)

    # File association
    assoc = subparsers.add_parser("file-assoc", help="Generate Windows file association")
    assoc.add_argument("--out", required=True, help="Output .reg file path")
    assoc.add_argument("--app-path", required=True, help="Path to app.py")
    assoc.add_argument("--python-path", required=True, help="Path to python executable")
    assoc.set_defaults(func=generate_file_association)

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(levelname)s: %(message)s"
    )

    args.func(args)


if __name__ == "__main__":
    main()
