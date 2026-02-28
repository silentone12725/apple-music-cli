English / [简体中文](./README-CN.md)

# Apple Music ALAC / Dolby Atmos Downloader

Original script by Sorrow. Modified with additional fixes, improvements, and streaming support.

### Special thanks to `chocomint` for creating `agent-arm64.js`

---

## Running with Docker

```bash
# Show help
docker run --network host -v ./downloads:/downloads ghcr.io/zhaarey/apple-music-downloader --help

# Download an album
docker run --network host -v ./downloads:/downloads ghcr.io/zhaarey/apple-music-downloader https://music.apple.com/us/album/children-of-forever/1443732441

# Download a single song
docker run --network host -v ./downloads:/downloads ghcr.io/zhaarey/apple-music-downloader --song "https://music.apple.com/us/album/bass-folk-song/1443732441?i=1443732453"

# Interactive select
docker run -it --network host -v ./downloads:/downloads ghcr.io/zhaarey/apple-music-downloader --select https://music.apple.com/us/album/children-of-forever/1443732441

# Download a playlist
docker run --network host -v ./downloads:/downloads ghcr.io/zhaarey/apple-music-downloader https://music.apple.com/us/playlist/taylor-swift-essentials/pl.3950454ced8c45a3b0cc693c2a7db97b

# Dolby Atmos
docker run --network host -v ./downloads:/downloads ghcr.io/zhaarey/apple-music-downloader --atmos https://music.apple.com/us/album/1989-taylors-version-deluxe/1713845538
```

Mount a custom `config.yaml`:

> **Note:** Make sure `config.yaml` exists in your current directory before running. If it does not exist, Docker will create an empty directory instead of a file.

```bash
docker run --network host -v ./downloads:/downloads -v ./config.yaml:/app/config.yaml ghcr.io/zhaarey/apple-music-downloader [args]
```

---

## Requirements

- [MP4Box](https://gpac.io/downloads/gpac-nightly-builds/) — must be installed and on your `PATH`
- [mp4decrypt](https://www.bento4.com/downloads/) — required for MV downloads
- [ffplay](https://ffmpeg.org/download.html) or [mpv](https://mpv.io/) — required for `--stream` mode
- [wrapper](https://github.com/zhaarey/wrapper) decryption server — must be running before use

---

## Supported Formats

| Format | Flag |
|---|---|
| ALAC lossless stereo | *(default)* |
| Dolby Atmos (EC-3) | `--atmos` |
| AAC stereo | `--aac` |
| AAC-LC stereo | `--aac --aac-type aac-lc` |
| AAC binaural | `--aac --aac-type aac-binaural` |
| AAC downmix | `--aac --aac-type aac-downmix` |
| Music Video | *(auto-detected from URL)* |

> `aac-lc`, MV downloads, and lyrics all require a valid `media-user-token` in `config.yaml`.

---

## Download

```bash
# Album
./apple-music-downloader https://music.apple.com/us/album/whenever-you-need-somebody-2022-remaster/1624945511

# Single song (two equivalent ways)
./apple-music-downloader --song "https://music.apple.com/us/album/album-name/ID?i=SONG_ID"
./apple-music-downloader https://music.apple.com/us/song/song-name/ID

# Playlist
./apple-music-downloader https://music.apple.com/us/playlist/taylor-swift-essentials/pl.3950454ced8c45a3b0cc693c2a7db97b

# Dolby Atmos
./apple-music-downloader --atmos https://music.apple.com/us/album/1989-taylors-version-deluxe/1713845538

# AAC
./apple-music-downloader --aac https://music.apple.com/us/album/1989-taylors-version-deluxe/1713845538

# Selective tracks (prompts for track numbers separated by spaces)
./apple-music-downloader --select https://music.apple.com/us/album/whenever-you-need-somebody-2022-remaster/1624945511

# All albums by an artist
./apple-music-downloader --all-album https://music.apple.com/us/artist/taylor-swift/159260351

# Debug / inspect audio quality without downloading
./apple-music-downloader --debug https://music.apple.com/us/album/1989-taylors-version-deluxe/1713845538
```

---

## Interactive Search

Search by keyword with arrow-key selection. Supported types: `song`, `album`, `artist`, `playlist`.

```bash
./apple-music-downloader --search song "blinding lights"
./apple-music-downloader --search album "after hours"
./apple-music-downloader --search artist "the weeknd"
./apple-music-downloader --search playlist "chill hits"
```

---

## Stream Mode (`--stream`)

Play music **directly without saving to disk**. Decryption happens to a RAM-backed temp file
(`/dev/shm`) for ALAC/Atmos, and AAC is piped in real time. Requires `ffplay` (FFmpeg) or `mpv`.

### Stream a single song

```bash
# By keyword (interactive search)
./apple-music-downloader --stream song "blinding lights"
./apple-music-downloader --stream --atmos song "blinding lights"
./apple-music-downloader --stream --aac song "something just like this"

# By direct URL
./apple-music-downloader --stream "https://music.apple.com/us/album/after-hours/1499377680?i=1499378615"
./apple-music-downloader --stream --atmos https://music.apple.com/us/album/after-hours/1499377680
```

### Stream an album

```bash
# By keyword (interactive search)
./apple-music-downloader --stream album "after hours"

# By direct URL
./apple-music-downloader --stream https://music.apple.com/us/album/after-hours/1499377680
```

### Stream a playlist

```bash
# By keyword (interactive search)
./apple-music-downloader --stream playlist "chill hits"
./apple-music-downloader --stream playlist "dark r&b"

# By direct URL
./apple-music-downloader --stream playlist https://music.apple.com/us/playlist/taylor-swift-essentials/pl.3950454ced8c45a3b0cc693c2a7db97b
./apple-music-downloader --stream https://music.apple.com/us/playlist/taylor-swift-essentials/pl.3950454ced8c45a3b0cc693c2a7db97b
```

### Playlist / album streaming behaviour

- Songs **auto-advance** — no prompt between tracks.
- The **next 2 tracks are prefetched in the background** while the current one plays (ALAC/Atmos),
  so each song starts with zero or near-zero wait.
- Press `q` inside `ffplay` / `mpv` to skip the current track and jump to the next one immediately.

---

## All Flags

| Flag | Description |
|---|---|
| `--stream` | Stream mode — play without saving to disk |
| `--atmos` | Dolby Atmos (EC-3) format |
| `--aac` | AAC format |
| `--aac-type` | AAC variant: `aac` (default), `aac-binaural`, `aac-downmix`, `aac-lc` |
| `--alac-max` | Max ALAC quality level (default from config) |
| `--atmos-max` | Max Atmos quality level (default from config) |
| `--song` | Single-song download mode |
| `--select` | Interactive track selection for albums/playlists |
| `--all-album` | Download all albums for an artist URL |
| `--search` | Interactive search: `--search [song|album|artist|playlist] "query"` |
| `--debug` | Show audio quality info without downloading |
| `--mv-audio-type` | MV audio track: `atmos`, `ac3`, `aac` |
| `--mv-max` | Max MV quality level |

---

## Getting `media-user-token` (required for AAC-LC, MV, and lyrics)

1. Open [Apple Music](https://music.apple.com) and log in.
2. Open Developer Tools → **Application → Storage → Cookies → `https://music.apple.com`**.
3. Find the cookie named `media-user-token` and copy its value.
4. Paste it into `media-user-token` in `config.yaml` and save.
5. Run the downloader as usual.

---

## Downloading Lyrics

Lyrics are downloaded automatically as `.lrc` files alongside the audio when `media-user-token`
is set. Word-by-word and line-by-line synced lyrics are both supported.

---

## Translation & Pronunciation Lyrics (Beta)

1. Open [Apple Music](https://beta.music.apple.com) and log in.
2. Open Developer Tools → `Network` tab.
3. Find a song with translation/pronunciation lyrics (K-Pop recommended).
4. Press `Ctrl+R`, play the song, and click the lyrics button.
5. In the `Fetch/XHR` tab, click the `syllable-lyrics` request.
6. From the request URL, copy the language value between `?l=` and `&extend`.
7. Paste it into `config.yaml` and save.
8. To disable pronunciation output: remove the value between `%5D=` and `&extend` in `config.yaml`.

> This feature is only available on the beta version of Apple Music.

[Chinese tutorial - see Method 3 for details](https://telegra.ph/Apple-Music-Alac高解析度无损音乐下载教程-04-02-2)
