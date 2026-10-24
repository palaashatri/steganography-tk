# GUI Screenshot Gallery

This gallery documents the desktop application's visible workflows and utility panels. Form screens show the available controls; completion screens were captured after running the corresponding action in the GUI.

## Hide Data and Reveal Data

### Image LSB

#### Image encode form and successful encode/decode

![Image encode form](hide-data-image-mode.jpg)

![Image encode completed](image-encode-complete.jpg)

![Image reveal form](reveal-data-image-mode.jpg)

![Image decode completed](image-decode-complete.jpg)

### Audio metadata

Audio payloads are stored in visible metadata tags; these screens demonstrate the metadata workflow, not hidden audio samples.

#### Audio metadata form, encode, reveal, and completed round trip

![Audio metadata encode form](hide-data-audio-mode.jpg)

![Audio metadata encode form with output path populated](audio-metadata-encode-complete.jpg)

![Audio metadata reveal form](reveal-data-audio-mode.jpg)

![Audio metadata extraction form with decoded output path](reveal-data-audio-round-trip.jpg)

### Video metadata

Video payloads in this mode are stored in visible container metadata. Use Video-frame LSB mode for pixel embedding.

#### Video metadata form, encode, reveal, and completed round trip

![Video metadata encode form](hide-data-video-mode.jpg)

![Video metadata encode form with output path populated](video-metadata-encode-complete.jpg)

![Video metadata reveal form](reveal-data-video-mode.jpg)

![Video metadata extraction form with decoded output path](reveal-data-video-round-trip.jpg)

### PDF metadata

#### PDF metadata encode, reveal, and extraction

![PDF metadata encode form](hide-data-pdf-mode.jpg)

![PDF metadata encode form with generated output path](pdf-metadata-encode-complete.jpg)

![PDF metadata reveal form](reveal-data-pdf-mode.jpg)

![PDF extraction completed](pdf-extract-complete.jpg)

## Advanced video-frame LSB

#### Video-frame controls, successful embedding, and extraction

![Advanced video-frame controls](advanced-video-frames.jpg)

![Video-frame form with generated MKV output path](video-frame-encode-complete.jpg)

![Video-frame extraction completed](video-frame-extract-complete.jpg)

## Batch image operations

#### Batch image forms and completed encode/decode

![Batch image operation forms](batch-operations.jpg)

![Batch image encode completed](batch-encode-complete.jpg)

![Batch image decode completed](batch-decode-complete.jpg)

## Analysis

The analysis view demonstrates image comparison, stego detection, and the security configuration summary.

![Analysis results](analysis-tools-results.jpg)

## Shared tools

The overview captures show the full tools panel: capacity calculator, key vault, templates, QR generator, portable decoder, Windows file association export, metadata viewer, SHA-256, file browser, and Gallery Builder.

#### Tools panel overview

![Tools panel top](tools-overview-top.jpg)

![Full Tools panel](tools-overview-full.jpg)

#### Capacity calculator result

![Image capacity calculated from a selected carrier](tools-capacity-calculated.jpg)

#### Key vault and templates

![Key vault save confirmation](tools-key-vault-saved.jpg)

![Template save confirmation](tools-template-saved.jpg)

![Template load confirmation](tools-template-loaded.jpg)

#### QR code generation and preview

![QR generator with generated output](tools-qr-generated.jpg)

![Generated QR opened in the app preview](open-generated-qr-preview.jpg)

#### Portable decoder and Windows file association

![Portable decoder ZIP created successfully](tools-portable-decoder-created.jpg)

![Windows file association export path](tools-file-association.jpg)

![Windows file association export completed](tools-file-association-created.jpg)

#### Metadata viewer, SHA-256, file browser, and Gallery Builder

![Metadata viewer result](tools-metadata-viewer.jpg)

![SHA-256 result](tools-sha256.jpg)

![File browser](tools-file-browser.jpg)

![Gallery Builder with selected input images and output ZIP path](tools-gallery-builder-selected.jpg)

![Gallery ZIP creation confirmation](tools-gallery-created.jpg)

## History, settings, and help

#### History rows with successful operations

![History image decode success](history-image-decode-success.jpg)

![History audio encode success](history-audio-encode-success.jpg)

#### Settings dialogs

![General settings](settings-general.jpg)

![Appearance settings](settings-appearance.jpg)

![Help dialog](help-dialog.jpg)

## Capture notes

- Audio and video metadata modes, and PDF metadata mode, make payload presence visible to metadata inspection tools. Encryption protects payload contents, not the existence of the metadata field.
- Captures use temporary demo files and paths. The visible sample messages are demonstration data, and `coastline-2026` is a demo PRNG key, not a recommended secret.
- All images originate from direct GUI captures. Tall captures are cropped to the relevant controls or results to remove unused window canvas; no controls or results have been altered.
- A still image can show the selected file and resulting preview, but it cannot prove the drag-and-drop gesture itself.
- Clipboard Paste and Key Vault Load are shown as available controls but were not activated: Paste reads the system clipboard, while Key Vault Load writes the decrypted key to it.
- The Gallery Builder setup image shows the selected image list and destination ZIP path; the separate confirmation image records successful ZIP creation. The portable decoder image likewise shows its completed ZIP action.
