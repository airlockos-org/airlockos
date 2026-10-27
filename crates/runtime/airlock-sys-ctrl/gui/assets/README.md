# Airlock logo

`logo.svg` is an unchanged copy of the logo supplied from
`/home/user/dev/airlock-org/assets/logo.svg`. The current artwork has a thin
red octagonal outline, a flat red doorway, two arrows and a transparent background.

`logo.png` is the supplied 512 × 512 transparent rendering from the same assets
directory. It is embedded in the binary for the header and native
window icon; running or building the app needs no external asset directory.

To regenerate it from the repository root with Inkscape installed:

```sh
inkscape crates/runtime/airlock-sys-ctrl/gui/assets/logo.svg \
  --export-area-page --export-width=512 --export-height=512 \
  --export-filename=crates/runtime/airlock-sys-ctrl/gui/assets/logo.png
```
