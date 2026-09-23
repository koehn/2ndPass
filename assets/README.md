# Mop app icon

`Mop.png` is the approved titanium vault on indigo master artwork, with transparent outer padding. `Mop.icns` contains the macOS icon representations from 16 through 1024 pixels. Packaging copies it into the app's Resources directory before signing and sets `CFBundleIconFile`.

To regenerate the ICNS after changing the master, run on macOS:

```sh
bash scripts/build-icon.sh "$PWD/assets/Mop.icns"
```

Artwork was refined using the built-in image generation tool from the selected vault concept. Final edit prompt:

> Refine this selected macOS Mop app icon into final artwork. Preserve its titanium vault on deep indigo rounded-square tile, front-facing circular vault door, three-spoke handle, left hinge, overall proportions and visual identity. Clean up edges and simplify fine brushed-metal noise, slightly strengthen handle contrast for legibility at small sizes. Keep subtle polished native macOS dimensionality. Square canvas with centered icon and even approximately 8% outer padding. Outside the rounded-square tile must be genuinely transparent alpha, no black or gray background, no cast shadow outside tile, no text, no new symbols. Deliver just the single finished icon.
