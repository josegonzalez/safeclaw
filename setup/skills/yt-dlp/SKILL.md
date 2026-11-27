---
name: yt-dlp
description: Download YouTube videos, audio, and subtitles/transcripts using yt-dlp.
---

# yt-dlp

Download YouTube videos, audio, and subtitles/transcripts.

## Setup

yt-dlp is installed in the image at `/usr/local/bin/yt-dlp`, pinned to a checked release. Use it as `yt-dlp`; don't download another copy.

## Examples

Download subtitles/transcript:
```bash
yt-dlp --write-auto-sub --sub-lang en --skip-download -o "/tmp/%(id)s" <url>
```

Download audio only:
```bash
yt-dlp -x --audio-format mp3 -o "/tmp/%(title)s.%(ext)s" <url>
```

Download video:
```bash
yt-dlp -o "/tmp/%(title)s.%(ext)s" <url>
```

Get video info (title, duration, description):
```bash
yt-dlp --print title --print duration_string --print description --no-download <url>
```

## Notes

- Subtitles are saved as `.vtt` files - read them to get the transcript
- Use `/tmp/` for downloads to avoid cluttering the working directory
