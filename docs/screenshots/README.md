# GUI Screenshot Gallery

This gallery documents the desktop application's visible workflows and utility panels. Form screens show the available controls; completion screens were captured after running the corresponding action in the GUI.

## Hide Data and Reveal Data

### Image LSB

<details>
<summary>Image encode form and successful encode/decode</summary>

![Image encode form](hide-data-image-mode.jpg)

![Image encode completed](image-encode-complete.jpg)

![Image reveal form](reveal-data-image-mode.jpg)

![Image decode completed](image-decode-complete.jpg)

</details>

### Audio metadata

Audio payloads are stored in visible metadata tags; these screens demonstrate the metadata workflow, not hidden audio samples.

<details>
<summary>Audio metadata form, encode, reveal, and completed round trip</summary>

![Audio metadata encode form](hide-data-audio-mode.jpg)

![Audio metadata encode completed](audio-metadata-encode-complete.jpg)

![Audio metadata reveal form](reveal-data-audio-mode.jpg)

![Audio metadata extraction completed](reveal-data-audio-round-trip.jpg)

</details>

### Video metadata

Video payloads in this mode are stored in visible container metadata. Use Video-frame LSB mode for pixel embedding.

<details>
<summary>Video metadata form, encode, reveal, and completed round trip</summary>

![Video metadata encode form](hide-data-video-mode.jpg)

![Video metadata encode completed](video-metadata-encode-complete.jpg)

![Video metadata reveal form](reveal-data-video-mode.jpg)

![Video metadata extraction completed](reveal-data-video-round-trip.jpg)

</details>

### PDF metadata

<details>
<summary>PDF metadata encode, reveal, and extraction</summary>

![PDF metadata encode form](hide-data-pdf-mode.jpg)

![PDF metadata encode completed](pdf-metadata-encode-complete.jpg)

![PDF metadata reveal form](reveal-data-pdf-mode.jpg)

![PDF extraction completed](pdf-extract-complete.jpg)

</details>

## Advanced video-frame LSB

<details>
<summary>Video-frame controls, successful embedding, and extraction</summary>

![Advanced video-frame controls](advanced-video-frames.jpg)

![Video-frame embedding completed](video-frame-encode-complete.jpg)

![Video-frame extraction completed](video-frame-extract-complete.jpg)

</details>

## Batch image operations

<details>
<summary>Batch image forms and completed encode/decode</summary>

![Batch image operation forms](batch-operations.jpg)

![Batch image encode completed](batch-encode-complete.jpg)

![Batch image decode completed](batch-decode-complete.jpg)

</details>

## Analysis

The analysis view demonstrates image comparison, stego detection, and the security configuration summary.

![Analysis results](analysis-tools-results.jpg)

## Shared tools

The overview captures show the full tools panel: capacity calculator, key vault, templates, QR generator, portable decoder, Windows file association export, metadata viewer, SHA-256, file browser, and Gallery Builder.

<details>
<summary>Tools panel overview</summary>

![Tools panel top](tools-overview-top.jpg)

![Full Tools panel](tools-overview-full.jpg)

</details>

<details>
<summary>Capacity calculator result</summary>

![Image capacity calculated from a selected carrier](tools-capacity-calculated.jpg)

</details>

<details>
<summary>Key vault and templates</summary>

![Key vault save confirmation](tools-key-vault-saved.jpg)

![Template save confirmation](tools-template-saved.jpg)

![Template load confirmation](tools-template-loaded.jpg)

</details>

<details>
<summary>QR code generation and preview</summary>

![QR generator with generated output](tools-qr-generated.jpg)

![Generated QR opened in the app preview](open-generated-qr-preview.jpg)

</details>

<details>
<summary>Portable decoder and Windows file association</summary>

![Portable decoder ZIP created successfully](tools-portable-decoder-created.jpg)

![Windows file association export path](tools-file-association.jpg)

![Windows file association export completed](tools-file-association-created.jpg)

</details>

<details>
<summary>Metadata viewer, SHA-256, file browser, and Gallery Builder</summary>

![Metadata viewer result](tools-metadata-viewer.jpg)

![SHA-256 result](tools-sha256.jpg)

![File browser](tools-file-browser.jpg)

![Gallery Builder with selected input images and output ZIP path](tools-gallery-builder-selected.jpg)

![Gallery ZIP creation confirmation](tools-gallery-created.jpg)

</details>

## History, settings, and help

<details>
<summary>History rows with successful operations</summary>

![History image decode success](history-image-decode-success.jpg)

![History audio encode success](history-audio-encode-success.jpg)

</details>

<details>
<summary>Settings dialogs</summary>

![General settings](settings-general.jpg)

![Appearance settings](settings-appearance.jpg)

</details>

![Help dialog](help-dialog.jpg)

## Capture notes

- Audio and video metadata modes, and PDF metadata mode, make payload presence visible to metadata inspection tools. Encryption protects payload contents, not the existence of the metadata field.
- Captures use temporary demo files and paths. The visible sample messages are demonstration data, and `coastline-2026` is a demo PRNG key, not a recommended secret.
- A still image can show the selected file and resulting preview, but it cannot prove the drag-and-drop gesture itself.
- Clipboard Paste and Key Vault Load are shown as available controls but were not activated: Paste reads the system clipboard, while Key Vault Load writes the decrypted key to it.
- The Gallery Builder setup image shows the selected image list and destination ZIP path; the separate confirmation image records successful ZIP creation. The portable decoder image likewise shows its completed ZIP action.
