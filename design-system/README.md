# RS3 — Night Signal

Static single-page design trial for an Audi RS3 “Night Signal” scroll experience.

## Run

```sh
python3 -m http.server 4173
```

Open <http://localhost:4173/> from this directory.

## Structure

```text
design-system/
├── index.html              # page, styles, SVG, canvas effects, and scroll runtime
├── .claude/launch.json     # local showcase launcher
└── .claude-launch-check    # launch metadata marker
```

Motion and Anime.js are loaded from jsDelivr at runtime.
