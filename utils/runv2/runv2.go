package runv2

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/itouakirai/mp4ff/mp4"
	"github.com/grafov/m3u8"

	"encoding/binary"
	"github.com/schollz/progressbar/v3"

	"main/utils/structs"
)
const prefetchKey = "skd://itunes.apple.com/P000000000/s1/e1"
var ErrTimeout = errors.New("response timed out")

type TimedResponseBody struct {
	timeout   time.Duration
	timer     *time.Timer
	threshold int
	body      io.Reader
}

func (b *TimedResponseBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if err != nil {
		return n, err
	}
	// fmt.Printf("Read %d bytes, buffer size %d bytes", n, len(p))
	if n >= b.threshold {
		b.timer.Reset(b.timeout)
	}
	return n, err
}


func Run(adamId string, playlistUrl string, outfile string, durationInMillis int, Config structs.ConfigSet) error {
	var err error
	var optstimeout uint
	optstimeout = 0
	timeout := time.Duration(optstimeout * uint(time.Millisecond))
	header := make(http.Header)

	// request media playlist
	req, err := http.NewRequest("GET", playlistUrl, nil)
	if err != nil {
		return err
	}
	req.Header = header
	// requesting an HLS playlist should be relatively fast, so we set the timeout directly on the client
	do, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return err
	}

	// parse m3u8
	segments, err := parseMediaPlaylist(do.Body)
	if err != nil {
		return err
	}
	segment := segments[0]
	if segment == nil {
		return errors.New("no segments extracted from playlist")
	}
	if segment.Limit <= 0 {
		return errors.New("non-byterange playlists are currently unsupported")
	}

	// get URL to the actual file
	parsedUrl, err := url.Parse(playlistUrl)
	if err != nil {
		return err
	}
	fileUrl, err := parsedUrl.Parse(segment.URI)
	if err != nil {
		return err
	}

	// request mp4
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	req, err = http.NewRequestWithContext(ctx, "GET", fileUrl.String(), nil)
	if err != nil {
		return err
	}
	req.Header = header

	var body io.Reader
	client := &http.Client{Timeout: timeout}
	if optstimeout > 0 {
		// create the timer before calling Do so that the timeout covers TCP handshake,
		// TLS handshake, sending the request and receiving HTTP headers
		timer := time.AfterFunc(timeout, func() { cancel(ErrTimeout) })
		do, err = client.Do(req)
		if err != nil {
			return err
		}
		defer do.Body.Close()
		body = &TimedResponseBody{
			timeout:   timeout,
			timer:     timer,
			threshold: 256,
			body:      do.Body,
		}
	} else {
		do, err = client.Do(req)
		if err != nil {
			return err
		}
		defer do.Body.Close()
		if do.ContentLength < int64(Config.MaxMemoryLimit * 1024 * 1024) {
			var buffer bytes.Buffer
			bar := progressbar.NewOptions64(
				do.ContentLength,
				progressbar.OptionClearOnFinish(),
				progressbar.OptionSetElapsedTime(false),
				progressbar.OptionSetPredictTime(false),
				progressbar.OptionShowElapsedTimeOnFinish(),
				progressbar.OptionShowCount(),
				progressbar.OptionEnableColorCodes(true),
				progressbar.OptionShowBytes(true),
				progressbar.OptionSetDescription("Downloading..."),
				progressbar.OptionSetTheme(progressbar.Theme{
					Saucer:        "",
					SaucerHead:    "",
					SaucerPadding: "",
					BarStart:      "",
					BarEnd:        "",
				}),
			)
			io.Copy(io.MultiWriter(&buffer, bar), do.Body)
			body = &buffer
			fmt.Print("Downloaded\n")
		} else {
			body = do.Body
		}
	}

	var totalLen int64
	totalLen = do.ContentLength
	// connect to decryptor
	//addr := fmt.Sprintf("127.0.0.1:10020")
	addr := Config.DecryptM3u8Port
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	//fmt.Print("Decrypting...\n")
	defer Close(conn)

	err = downloadAndDecryptFile(conn, body, outfile, adamId, segments, totalLen, durationInMillis, Config)
	if err != nil {
		return err
	}
	fmt.Print("Decrypted\n")
	return nil
}

// RunStreamWriter fetches and decrypts the ALAC/Atmos track fragment-by-fragment,
// writing each decrypted fragment to w immediately. Designed to be called with an
// io.Pipe writer so the consumer (ffplay) starts playing within one fragment's worth
// of data rather than waiting for the full download+decrypt cycle.
//
// The file download uses HTTP/1.1 (not H2) to avoid Apple CDN sending a GOAWAY
// frame when the reader is slow due to TCP decrypt round-trips.
func RunStreamWriter(adamId string, playlistUrl string, w io.Writer, durationInMillis int, Config structs.ConfigSet) error {
	// Playlist fetch can use the default client.
	req, err := http.NewRequest("GET", playlistUrl, nil)
	if err != nil {
		return err
	}
	do, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	segments, err := parseMediaPlaylist(do.Body)
	if err != nil {
		return err
	}
	segment := segments[0]
	if segment == nil {
		return errors.New("no segments extracted from playlist")
	}
	if segment.Limit <= 0 {
		return errors.New("non-byterange playlists are currently unsupported")
	}
	parsedUrl, err := url.Parse(playlistUrl)
	if err != nil {
		return err
	}
	fileUrl, err := parsedUrl.Parse(segment.URI)
	if err != nil {
		return err
	}
	// Force HTTP/1.1 for the actual media download.
	// Apple's H2 CDN sends GOAWAY under slow-reader backpressure (TCP decrypt RTT).
	http11 := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: false,
			TLSNextProto:      map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
		},
	}
	do2, err := http11.Get(fileUrl.String())
	if err != nil {
		return err
	}
	defer do2.Body.Close()
	conn, err := net.Dial("tcp", Config.DecryptM3u8Port)
	if err != nil {
		return err
	}
	defer Close(conn)
	return decryptFragmentsTo(conn, do2.Body, w, adamId, segments, durationInMillis)
}

// decryptFragmentsTo is the shared streaming-decrypt core: reads fMP4 fragments
// from in, decrypts via the agent TCP conn, and writes each fragment to w immediately.
func decryptFragmentsTo(conn io.ReadWriter, in io.Reader, w io.Writer, adamId string, playlistSegments []*m3u8.MediaSegment, durationInMillis int) error {
	inBuf := bufio.NewReader(in)
	outBuf := bufio.NewWriterSize(w, 256*1024)

	init, offset, err := ReadInitSegment(inBuf)
	if err != nil {
		return err
	}
	if init == nil {
		return errors.New("no init segment found")
	}

	originalInitSize := offset
	if len(init.Moov.Traks) > 0 && durationInMillis > 0 {
		timescale := init.Moov.Traks[0].Mdia.Mdhd.Timescale
		fragmentDuration := int64(uint64(durationInMillis) * uint64(timescale) / 1000)
		if init.Moov.Mvex == nil {
			init.Moov.AddChild(&mp4.MvexBox{})
		}
		if init.Moov.Mvex.Mehd == nil {
			init.Moov.Mvex.AddChild(&mp4.MehdBox{Version: 1, FragmentDuration: fragmentDuration})
		} else {
			init.Moov.Mvex.Mehd.FragmentDuration = fragmentDuration
		}
	}
	sizeDiff := int64(init.Size()) - int64(originalInitSize)

	tracks, err := TransformInit(init)
	if err != nil {
		return err
	}
	_ = sanitizeInit(init)
	if err = init.Encode(outBuf); err != nil {
		return err
	}
	if err = outBuf.Flush(); err != nil {
		return err
	}

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	fragN := 0
	for {
		frag, newOffset, ferr := ReadNextFragment(inBuf, offset)
		rawBytes := newOffset - offset
		offset = newOffset
		if ferr != nil {
			return ferr
		}
		if frag == nil {
			break
		}
		if sizeDiff > 0 && frag.Moof != nil {
			for _, traf := range frag.Moof.Trafs {
				if traf.Tfhd != nil && traf.Tfhd.HasBaseDataOffset() {
					traf.Tfhd.BaseDataOffset += uint64(sizeDiff)
				}
			}
		}
		seg := playlistSegments[fragN]
		if seg == nil {
			return errors.New("segment number out of sync")
		}
		key := seg.Key
		if key != nil {
			if fragN != 0 {
				SwitchKeys(rw)
			}
			if key.URI == prefetchKey {
				SendString(rw, "0")
			} else {
				SendString(rw, adamId)
			}
			SendString(rw, key.URI)
		}
		if err = DecryptFragment(frag, tracks, rw); err != nil {
			return fmt.Errorf("decryptFragment: %w", err)
		}
		if err = frag.Encode(outBuf); err != nil {
			return err
		}
		if err = outBuf.Flush(); err != nil {
			return err
		}
		fragN++
		fmt.Printf("\r⚡ ALAC fragment %d piped to player (%d B)", fragN, rawBytes)
	}
	fmt.Printf("\r🎵 ALAC stream complete (%d fragments)       \n", fragN)
	return outBuf.Flush()
}

// RunStream downloads the entire encrypted fMP4 file into memory first so the
// network download runs at full speed without DRM-decryption round-trips stalling it.
// Once the file is in a buffer it decrypts every fragment one-by-one, flushing each
// to outfile immediately so a media player reading the growing file sees audio data
// as soon as the first fragment is ready.
func RunStream(adamId string, playlistUrl string, outfile string, Config structs.ConfigSet) error {
	header := make(http.Header)

	// Fetch and parse the media playlist
	req, err := http.NewRequest("GET", playlistUrl, nil)
	if err != nil {
		return err
	}
	req.Header = header
	do, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	segments, err := parseMediaPlaylist(do.Body)
	if err != nil {
		return err
	}
	segment := segments[0]
	if segment == nil {
		return errors.New("no segments extracted from playlist")
	}
	if segment.Limit <= 0 {
		return errors.New("non-byterange playlists are currently unsupported")
	}

	parsedUrl, err := url.Parse(playlistUrl)
	if err != nil {
		return err
	}
	fileUrl, err := parsedUrl.Parse(segment.URI)
	if err != nil {
		return err
	}

	// Phase 1: download entire encrypted file at full network speed
	req, err = http.NewRequest("GET", fileUrl.String(), nil)
	if err != nil {
		return err
	}
	req.Header = header
	do, err = (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer do.Body.Close()

	var encBuf bytes.Buffer
	bar := progressbar.NewOptions64(
		do.ContentLength,
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetElapsedTime(false),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionShowCount(),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetDescription("Downloading..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "",
			SaucerHead:    "",
			SaucerPadding: "",
			BarStart:      "",
			BarEnd:        "",
		}),
	)
	if _, err = io.Copy(io.MultiWriter(&encBuf, bar), do.Body); err != nil {
		return err
	}
	fmt.Print("Downloaded\n")

	// Phase 2: decrypt fragment-by-fragment directly to outfile (progressive writes)
	conn, err := net.Dial("tcp", Config.DecryptM3u8Port)
	if err != nil {
		return err
	}
	defer Close(conn)

	// MaxMemoryLimit=0 forces downloadAndDecryptFile to write every fragment to disk
	// immediately instead of buffering in RAM, so the HTTP server can serve growing bytes.
	streamConfig := Config
	streamConfig.MaxMemoryLimit = 0

	err = downloadAndDecryptFile(conn, &encBuf, outfile, adamId, segments, int64(encBuf.Len()), 0, streamConfig)
	if err != nil {
		return err
	}
	fmt.Print("Decrypted\n")
	return nil
}

// DecryptToBuffer downloads the encrypted fMP4 at full network speed into RAM,
// then decrypts every fragment into a second in-memory buffer and returns it.
// The caller can pipe the buffer directly to a media player's stdin.
func DecryptToBuffer(adamId string, playlistUrl string, Config structs.ConfigSet) (*bytes.Buffer, error) {
	header := make(http.Header)

	req, err := http.NewRequest("GET", playlistUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header = header
	do, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	segments, err := parseMediaPlaylist(do.Body)
	if err != nil {
		return nil, err
	}
	segment := segments[0]
	if segment == nil {
		return nil, errors.New("no segments extracted from playlist")
	}

	parsedUrl, err := url.Parse(playlistUrl)
	if err != nil {
		return nil, err
	}
	fileUrl, err := parsedUrl.Parse(segment.URI)
	if err != nil {
		return nil, err
	}

	// Phase 1: download encrypted file at full network speed
	req, err = http.NewRequest("GET", fileUrl.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header = header
	do, err = (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer do.Body.Close()

	var encBuf bytes.Buffer
	bar := progressbar.NewOptions64(
		do.ContentLength,
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetElapsedTime(false),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionShowCount(),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetDescription("Downloading..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "",
			SaucerHead:    "",
			SaucerPadding: "",
			BarStart:      "",
			BarEnd:        "",
		}),
	)
	if _, err = io.Copy(io.MultiWriter(&encBuf, bar), do.Body); err != nil {
		return nil, err
	}
	fmt.Print("Downloaded\n")

	// Phase 2: decrypt every fragment into an output buffer in RAM
	conn, err := net.Dial("tcp", Config.DecryptM3u8Port)
	if err != nil {
		return nil, err
	}
	defer Close(conn)

	inBuf := bufio.NewReader(&encBuf)
	init, offset, err := ReadInitSegment(inBuf)
	if err != nil {
		return nil, err
	}
	if init == nil {
		return nil, errors.New("no init segment found")
	}
	tracks, err := TransformInit(init)
	if err != nil {
		return nil, err
	}
	if err = sanitizeInit(init); err != nil {
		fmt.Printf("Warning: unable to sanitize init completely: %s\n", err)
	}

	var outBuf bytes.Buffer
	w := bufio.NewWriter(&outBuf)
	if err = init.Encode(w); err != nil {
		return nil, err
	}

	totalLen := int64(encBuf.Len()) + int64(offset)
	decBar := progressbar.NewOptions64(totalLen,
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetElapsedTime(false),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionShowCount(),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetDescription("Decrypting..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "",
			SaucerHead:    "",
			SaucerPadding: "",
			BarStart:      "",
			BarEnd:        "",
		}),
	)
	decBar.Add64(int64(offset))

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	for i := 0; ; i++ {
		rawOffset := offset
		frag, newOffset, err := ReadNextFragment(inBuf, offset)
		rawOffset = newOffset - rawOffset
		offset = newOffset
		if err != nil {
			return nil, err
		}
		if frag == nil {
			break
		}
		seg := segments[i]
		if seg == nil {
			return nil, errors.New("segment number out of sync")
		}
		if key := seg.Key; key != nil {
			if i != 0 {
				SwitchKeys(rw)
			}
			if key.URI == prefetchKey {
				SendString(rw, "0")
			} else {
				SendString(rw, adamId)
			}
			SendString(rw, key.URI)
		}
		if err = DecryptFragment(frag, tracks, rw); err != nil {
			return nil, fmt.Errorf("decryptFragment: %w", err)
		}
		if err = frag.Encode(w); err != nil {
			return nil, err
		}
		decBar.Add64(int64(rawOffset))
	}
	if err = w.Flush(); err != nil {
		return nil, err
	}
	fmt.Print("Decrypted\n")
	return &outBuf, nil
}

func downloadAndDecryptFile(conn io.ReadWriter, in io.Reader, outfile string,
	adamId string, playlistSegments []*m3u8.MediaSegment, totalLen int64, durationInMillis int, Config structs.ConfigSet) error {
	var buffer bytes.Buffer
	var outBuf *bufio.Writer
	MaxMemorySize := int64(Config.MaxMemoryLimit * 1024 * 1024)
	inBuf := bufio.NewReader(in)
	if totalLen <= MaxMemorySize {
		outBuf = bufio.NewWriter(&buffer)
	} else {
		ofh, err := os.Create(outfile)
		if err != nil {
			return err
		}
		defer ofh.Close()
		outBuf = bufio.NewWriter(ofh)
	}
	init, offset, err := ReadInitSegment(inBuf)
	if err != nil {
		return err
	}
	if init == nil {
		return errors.New("no init segment found")
	}

	// Capture original init size (bytes read from the stream) before any modifications.
	originalInitSize := offset

	// Inject mehd (Movie Extends Header) box so libavformat knows the full duration.
	// Without it, ffplay derives duration from only the first moof fragment (~14.95s).
	if len(init.Moov.Traks) > 0 && durationInMillis > 0 {
		timescale := init.Moov.Traks[0].Mdia.Mdhd.Timescale
		fragmentDuration := int64(uint64(durationInMillis) * uint64(timescale) / 1000)
		if init.Moov.Mvex == nil {
			mvex := &mp4.MvexBox{}
			init.Moov.AddChild(mvex)
		}
		if init.Moov.Mvex.Mehd == nil {
			mehd := &mp4.MehdBox{
				Version:          1,
				FragmentDuration: fragmentDuration,
			}
			init.Moov.Mvex.AddChild(mehd)
		} else {
			init.Moov.Mvex.Mehd.FragmentDuration = fragmentDuration
		}
	}

	// Calculate how many bytes the mehd injection added to the init segment.
	// Fragments that use an absolute BaseDataOffset must be shifted by this amount.
	newInitSize := init.Size()
	sizeDiff := int64(newInitSize) - int64(originalInitSize)

	tracks, err := TransformInit(init)
	if err != nil {
		return err
	}
	err = sanitizeInit(init)
	if err != nil {
		// errors returned by sanitizeInit are non-fatal
		fmt.Printf("Warning: unable to sanitize init completely: %s\n", err)
	}
	err = init.Encode(outBuf)
	if err != nil {
		return err
	}
	if err = outBuf.Flush(); err != nil {
		return err
	}

	// 'segment' in m3u8 == 'fragment' in mp4ff
	//fmt.Println("Starting decryption...")
	bar := progressbar.NewOptions64(totalLen,
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetElapsedTime(false),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionShowCount(),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetDescription("Decrypting..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "",
			SaucerHead:    "",
			SaucerPadding: "",
			BarStart:      "",
			BarEnd:        "",
		}),
	)
	bar.Add64(int64(offset))
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	for i := 0; ; i++ {
		var frag *mp4.Fragment
		rawoffset := offset
		frag, offset, err = ReadNextFragment(inBuf, offset)
		rawoffset = offset - rawoffset
		if err != nil {
			return err
		}
		if frag == nil {
			// check offset against Content-Length?
			break
		}

		// If the init segment grew (e.g. mehd injection), shift any absolute
		// BaseDataOffset pointers so the player can locate the audio payload.
		if sizeDiff > 0 && frag.Moof != nil {
			for _, traf := range frag.Moof.Trafs {
				if traf.Tfhd != nil && traf.Tfhd.HasBaseDataOffset() {
					traf.Tfhd.BaseDataOffset += uint64(sizeDiff)
				}
			}
		}
		segment := playlistSegments[i]
		if segment == nil {
			return errors.New("segment number out of sync")
		}
		key := segment.Key
		if key != nil {
			if i != 0 {
				SwitchKeys(rw)
			}
			if key.URI == prefetchKey {
				SendString(rw, "0")
			} else {
				SendString(rw, adamId)
			}
			SendString(rw, key.URI)
		}
		// flushes the buffer
		err = DecryptFragment(frag, tracks, rw)
		if err != nil {
			return fmt.Errorf("decryptFragment: %w", err)
		}
		err = frag.Encode(outBuf)
		if err != nil {
			return err
		}
		// Flush each fragment to disk immediately so readers of the growing file
		// (e.g. the HTTP streaming server) can see it without waiting for the next fragment.
		if err = outBuf.Flush(); err != nil {
			return err
		}
		bar.Add64(int64(rawoffset))
	}
	err = outBuf.Flush()
	if err != nil {
		return err
	}
	if totalLen <= MaxMemorySize {
		ofh, err := os.Create(outfile)
		if err != nil {
			return err
		}
		defer ofh.Close()

		_, err = ofh.Write(buffer.Bytes())
		if err != nil {
			return err
		}
	}
	return nil
}

// Remove boxes in the init segment that are known to cause compatibility issues
func sanitizeInit(init *mp4.InitSegment) error {
	traks := init.Moov.Traks
	if len(traks) > 1 {
		return errors.New("more than 1 track found")
	}

	// Zero out the duration fields in moov/tkhd/mdhd.
	// Apple's encoder writes the first HLS segment's duration here (~15s), which is
	// non-standard for fragmented MP4: per ISO 14496-12 these MUST be 0 in fMP4 files.
	// Players like ffplay stop exactly at this declared duration, cutting off the rest
	// of the track. Zeroing them forces players to derive duration from the fragments.
	init.Moov.Mvhd.Duration = 0
	trak := traks[0]
	trak.Tkhd.Duration = 0
	trak.Mdia.Mdhd.Duration = 0

	// Zero the sample tables in stbl. In a valid fMP4 these MUST be empty — all sample
	// timing and offsets live inside the moof fragments. Apple's encoder populates stts
	// with one HLS segment's worth of entries (~15s), causing players to stop after that
	// segment even though more moof data follows in the stream.
	stbl := trak.Mdia.Minf.Stbl
	if stbl.Stts != nil {
		stbl.Stts.SampleCount = []uint32{}
		stbl.Stts.SampleTimeDelta = []uint32{}
	}
	if stbl.Stco != nil {
		stbl.Stco.ChunkOffset = []uint32{}
	}
	if stbl.Stsc != nil {
		stbl.Stsc.Entries = nil
	}
	if stbl.Stsz != nil {
		stbl.Stsz.SampleSize = nil
		stbl.Stsz.SampleNumber = 0
		stbl.Stsz.SampleUniformSize = 0
	}

	// Remove duplicate ec-3 or alac boxes in stsd since some programs (e.g. cuetools) don't
	// like it when there's more than 1 entry in stsd.
	// Every audio track contains two of these boxes because two IVs are needed to decrypt the
	// track. The two boxes become identical after removing encryption info.
	stsd := traks[0].Mdia.Minf.Stbl.Stsd
	if stsd.SampleCount == 1 {
		return nil
	}
	if stsd.SampleCount > 2 {
		return fmt.Errorf("expected only 1 or 2 entries in stsd, got %d", stsd.SampleCount)
	}
	children := stsd.Children
	if children[0].Type() != children[1].Type() {
		return errors.New("children in stsd are not of the same type")
	}
	stsd.Children = children[:1]
	stsd.SampleCount = 1
	return nil
}

// Workaround for m3u8 not supporting multiple keys - remove
// PlayReady and Widevine
func filterResponse(f io.Reader) (*bytes.Buffer, error) {
	buf := &bytes.Buffer{}
	scanner := bufio.NewScanner(f)

	prefix := []byte("#EXT-X-KEY:")
	keyFormat := []byte("streamingkeydelivery")
	for scanner.Scan() {
		lineBytes := scanner.Bytes()
		if bytes.HasPrefix(lineBytes, prefix) && !bytes.Contains(lineBytes, keyFormat) {
			continue
		}
		_, err := buf.Write(lineBytes)
		if err != nil {
			return nil, err
		}
		_, err = buf.WriteString("\n")
		if err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return buf, nil
}

func parseMediaPlaylist(r io.ReadCloser) ([]*m3u8.MediaSegment, error) {
	defer r.Close()
	playlistBuf, err := filterResponse(r)
	if err != nil {
		return nil, err
	}

	playlist, listType, err := m3u8.Decode(*playlistBuf, true)
	if err != nil {
		return nil, err
	}

	if listType != m3u8.MEDIA {
		return nil, errors.New("m3u8 not of media type")
	}

	mediaPlaylist := playlist.(*m3u8.MediaPlaylist)
	return mediaPlaylist.Segments, nil
}

//pasing
func ReadInitSegment(r io.Reader) (*mp4.InitSegment, uint64, error) {
	var offset uint64 = 0
	init := mp4.NewMP4Init()
	for i := 0; i < 2; i++ {
		box, err := mp4.DecodeBox(offset, r)
		if err != nil {
			return nil, offset, err
		}
		boxType := box.Type()
		if boxType != "ftyp" && boxType != "moov" {
			return nil, offset, fmt.Errorf("unexpected box type %s, should be ftyp or moov", boxType)
		}
		init.AddChild(box)
		offset += box.Size()
	}
	return init, offset, nil
}

// Get the next fragment. Returns nil and no error on EOF
func ReadNextFragment(r io.Reader, offset uint64) (*mp4.Fragment, uint64, error) {
	frag := mp4.NewFragment()
	for {
		box, err := mp4.DecodeBox(offset, r)
		if err == io.EOF {
			return nil, offset, nil
		}
		if err != nil {
			return nil, offset, err
		}
		boxType := box.Type()
		// fmt.Printf("processing %s, box starts @ offset %d\n", boxType, offset)
		offset += box.Size()
		if boxType == "moof" || boxType == "emsg" || boxType == "prft" {
			frag.AddChild(box)
			continue
		}
		if boxType == "mdat" {
			frag.AddChild(box)
			break
		}
		fmt.Printf("ignoring a %s box found mid-stream", boxType)
	}
	// only 1 mdat box in fragment, meaning that the box doesn't have a preceding moof box
	if frag.Moof == nil {
		return nil, offset, fmt.Errorf("more than one mdat box in fragment (box ends @ offset %d)", offset)
	}
	return frag, offset, nil
}

// Return a new slice of boxes with encryption-related sbgp and sgpd removed,
// and the total number of bytes removed.
// Non-encryption-related ones such as 'roll' are left untouched.
func FilterSbgpSgpd(children []mp4.Box) ([]mp4.Box, uint64) {
	var bytesRemoved uint64 = 0
	remainingChildren := make([]mp4.Box, 0, len(children))
	for _, child := range children {
		switch box := child.(type) {
		case *mp4.SbgpBox:
			if box.GroupingType == "seam" || box.GroupingType == "seig" {
				bytesRemoved += child.Size()
				continue
			}
		case *mp4.SgpdBox:
			if box.GroupingType == "seam" || box.GroupingType == "seig" {
				bytesRemoved += child.Size()
				continue
			}
		}
		remainingChildren = append(remainingChildren, child)
	}
	return remainingChildren, bytesRemoved
}

// Get decryption info for tracks from init segment and remove encryption-related boxes
func TransformInit(init *mp4.InitSegment) (map[uint32]mp4.DecryptTrackInfo, error) {
	di, err := mp4.DecryptInit(init)
	tracks := make(map[uint32]mp4.DecryptTrackInfo, len(di.TrackInfos))
	for _, ti := range di.TrackInfos {
		tracks[ti.TrackID] = ti
	}
	if err != nil {
		return tracks, err
	}
	// remove encryption-related sbgp and sgpd
	for _, trak := range init.Moov.Traks {
		stbl := trak.Mdia.Minf.Stbl
		stbl.Children, _ = FilterSbgpSgpd(stbl.Children)
	}
	return tracks, nil
}
//remote
// Reset the loops on the script's end and close the connection
func Close(conn io.WriteCloser) error {
	defer conn.Close()
	_, err := conn.Write([]byte{0, 0, 0, 0, 0})
	return err
}

func SwitchKeys(conn io.Writer) error {
	_, err := conn.Write([]byte{0, 0, 0, 0})
	return err
}

// Send id or keyUri
func SendString(conn io.Writer, uri string) error {
	_, err := conn.Write([]byte{byte(len(uri))})
	if err != nil {
		return err
	}
	_, err = io.WriteString(conn, uri)
	return err
}



func cbcsFullSubsampleDecrypt(data []byte, conn *bufio.ReadWriter) error {
	// Drops 4 last bits -> multiple of 16
	// It wouldn't hurt to send the remaining bytes also because the decryption
	// function would just return them as-is, but we're truncating the data here
	// for clarity and interoperability
	truncatedLen := len(data) & ^0xf
	// send the whole chunk at once
	err := binary.Write(conn, binary.LittleEndian, uint32(truncatedLen))
	if err != nil {
		return err
	}
	_, err = conn.Write(data[:truncatedLen])
	if err != nil {
		return err
	}
	err = conn.Flush()
	if err != nil {
		return err
	}
	_, err = io.ReadFull(conn, data[:truncatedLen])
	return err
}

func cbcsStripeDecrypt(data []byte, conn *bufio.ReadWriter, decryptBlockLen, skipBlockLen int) error {
	size := len(data)

	// block too small, ignore
	if size < decryptBlockLen {
		return nil
	}

	// number of encrypted blocks in this sample
	count := ((size - decryptBlockLen) / (decryptBlockLen + skipBlockLen)) + 1
	totalLen := count * decryptBlockLen

	err := binary.Write(conn, binary.LittleEndian, uint32(totalLen))
	if err != nil {
		return err
	}

	pos := 0
	for {
		if size-pos < decryptBlockLen { // Leave the rest
			break
		}
		_, err = conn.Write(data[pos : pos+decryptBlockLen])
		if err != nil {
			return err
		}
		pos += decryptBlockLen
		if size-pos < skipBlockLen {
			break
		}
		pos += skipBlockLen
	}
	err = conn.Flush()
	if err != nil {
		return err
	}

	pos = 0
	for {
		if size-pos < decryptBlockLen {
			break
		}
		_, err = io.ReadFull(conn, data[pos:pos+decryptBlockLen])
		if err != nil {
			return err
		}
		pos += decryptBlockLen
		if size-pos < skipBlockLen {
			break
		}
		pos += skipBlockLen
	}
	return nil
}

// Decryption function dispatcher
func cbcsDecryptRaw(data []byte, conn *bufio.ReadWriter, decryptBlockLen, skipBlockLen int) error {
	if skipBlockLen == 0 {
		// Full encryption of subsamples
		// e.g. Apple Music ALAC
		return cbcsFullSubsampleDecrypt(data, conn)
	} else {
		// Pattern (stripe) encryption of subsamples
		// e.g. most AVC and HEVC applications
		return cbcsStripeDecrypt(data, conn, decryptBlockLen, skipBlockLen)
	}
}

// Decrypt a cbcs-encrypted sample in-place
func cbcsDecryptSample(sample []byte, conn *bufio.ReadWriter,
	subSamplePatterns []mp4.SubSamplePattern, tenc *mp4.TencBox) error {

	decryptBlockLen := int(tenc.DefaultCryptByteBlock) * 16
	skipBlockLen := int(tenc.DefaultSkipByteBlock) * 16
	var pos uint32 = 0

	// Full sample encryption
	if len(subSamplePatterns) == 0 {
		return cbcsDecryptRaw(sample, conn, decryptBlockLen, skipBlockLen)
	}

	// Has subsamples
	for j := 0; j < len(subSamplePatterns); j++ {
		ss := subSamplePatterns[j]
		pos += uint32(ss.BytesOfClearData)

		// Nothing to decrypt!
		if ss.BytesOfProtectedData <= 0 {
			continue
		}

		err := cbcsDecryptRaw(sample[pos:pos+ss.BytesOfProtectedData],
			conn, decryptBlockLen, skipBlockLen)
		if err != nil {
			return err
		}
		pos += ss.BytesOfProtectedData
	}

	return nil
}

// Decrypt an array of cbcs-encrypted samples in-place
func cbcsDecryptSamples(samples []mp4.FullSample, conn *bufio.ReadWriter,
	tenc *mp4.TencBox, senc *mp4.SencBox) error {

	for i := range samples {
		var subSamplePatterns []mp4.SubSamplePattern
		if len(senc.SubSamples) != 0 {
			subSamplePatterns = senc.SubSamples[i]
		}
		err := cbcsDecryptSample(samples[i].Data, conn, subSamplePatterns, tenc)
		if err != nil {
			return err
		}
	}
	return nil
}

func DecryptFragment(frag *mp4.Fragment, tracks map[uint32]mp4.DecryptTrackInfo, conn *bufio.ReadWriter) error {
	moof := frag.Moof
	var bytesRemoved uint64 = 0

	for _, traf := range moof.Trafs {
		ti, ok := tracks[traf.Tfhd.TrackID]
		if !ok {
			return fmt.Errorf("could not find decryption info for track %d", traf.Tfhd.TrackID)
		}
		if ti.Sinf == nil {
			// unencrypted track
			continue
		}

		schemeType := ti.Sinf.Schm.SchemeType
		if schemeType != "cbcs" {
			return fmt.Errorf("scheme type %s not supported", schemeType)
		}
		hasSenc, isParsed := traf.ContainsSencBox()
		if !hasSenc {
			return fmt.Errorf("no senc box in traf")
		}

		var senc *mp4.SencBox
		if traf.Senc != nil {
			senc = traf.Senc
		} else {
			senc = traf.UUIDSenc.Senc
		}

		if !isParsed {
			// simply ignore sbgp and sgpd
			// "Sample To Group Box ('sbgp') and Sample Group Description Box ('sgpd')
			// of type 'seig' are used to indicate the KID applied to each sample, and changes
			// to KIDs over time (i.e. 'key rotation')"
			// (ref: https://dashif.org/docs/DASH-IF-IOP-v3.2.pdf)
			err := senc.ParseReadBox(ti.Sinf.Schi.Tenc.DefaultPerSampleIVSize, traf.Saiz)
			if err != nil {
				return err
			}
		}

		samples, err := frag.GetFullSamples(ti.Trex)
		if err != nil {
			return err
		}

		err = cbcsDecryptSamples(samples, conn, ti.Sinf.Schi.Tenc, senc)
		if err != nil {
			return err
		}

		bytesRemoved += traf.RemoveEncryptionBoxes()
	}
	_, psshBytesRemoved := moof.RemovePsshs()
	bytesRemoved += psshBytesRemoved
	for _, traf := range moof.Trafs {
		for _, trun := range traf.Truns {
			trun.DataOffset -= int32(bytesRemoved)
		}
	}

	return nil
}
