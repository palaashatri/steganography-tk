"""Bounded image statistics for a cautious LSB self-check.

The pair-values chi-square statistic is a heuristic for adjacent even/odd
intensity counts. It cannot identify hidden data or establish undetectability.
"""

from __future__ import annotations

from PIL import Image


def lsb_pair_chi_square(image: Image.Image) -> float:
    """Return a pair-values chi-square statistic over the RGB channel values.

    For each adjacent pair ``(2k, 2k + 1)``, the contribution is
    ``(even_count - odd_count) ** 2 / (even_count + odd_count)``. This
    statistic is only a heuristic: natural image content, image processing,
    and embedding methods affect it, so it cannot prove that data is present
    or absent and cannot guarantee that an image is undetectable.
    """
    channel_histograms = image.convert("RGB").histogram()
    counts = [
        channel_histograms[value]
        + channel_histograms[256 + value]
        + channel_histograms[512 + value]
        for value in range(256)
    ]

    statistic = 0.0
    for even_value in range(0, 256, 2):
        even_count = counts[even_value]
        odd_count = counts[even_value + 1]
        pair_count = even_count + odd_count
        if pair_count:
            difference = even_count - odd_count
            statistic += difference * difference / pair_count
    return float(statistic)
