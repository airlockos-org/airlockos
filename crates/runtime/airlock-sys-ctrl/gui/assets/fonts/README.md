# Inter

The source `InterVariable.woff2` and its SIL Open Font License 1.1 were copied
unchanged from `website/public/fonts/` in the sibling Airlock website project.
The website records upstream provenance as `rsms/inter` revision
`353b61b9f4430d5f420d56605a6e7993e0941470`,
`docs/font-files/InterVariable.woff2`.

Source SHA-256:
`693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3`.

The three TTF files are static instances for egui's native font renderer:
regular (400), medium (500) and semibold (600), all at optical size 14 for the
app's interface text. Their glyphs come from the same website font. The source,
generated instances and license are retained locally and need no font service
or system font installation at runtime.

These instances were generated with fontTools 4.58.5 and Brotli 1.1.0,
preserving the source timestamps. Builds use the committed TTFs directly.
Regeneration is only needed when changing the source font or instance settings.
