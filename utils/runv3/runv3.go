package runv3

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"

	"github.com/go-resty/resty/v2"
	"google.golang.org/protobuf/proto"

	cdm "main/utils/runv3/cdm"
	key "main/utils/runv3/key"
	"os"

	"bytes"
	"errors"
	"io"

	"github.com/itouakirai/mp4ff/mp4"

	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"sync"

	"github.com/grafov/m3u8"
	"github.com/schollz/progressbar/v3"
)

type PlaybackLicense struct {
	ErrorCode  int    `json:"errorCode"`
	License    string `json:"license"`
	RenewAfter int    `json:"renew-after"`
	Status     int    `json:"status"`
}

// kidKeyCache caches Widevine decryption keys by KID (base64).
// Subsequent plays of the same track skip the CDM round-trip entirely.
var kidKeyCache sync.Map

func getPSSH(contentId string, kidBase64 string) (string, error) {
	kidBytes, err := base64.StdEncoding.DecodeString(kidBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 KID: %v", err)
	}
	contentIdEncoded := base64.StdEncoding.EncodeToString([]byte(contentId))
	algo := cdm.WidevineCencHeader_AESCTR
	widevineCencHeader := &cdm.WidevineCencHeader{
		KeyId:     [][]byte{kidBytes},
		Algorithm: &algo,
		Provider:  new(string),
		ContentId: []byte(contentIdEncoded),
		Policy:    new(string),
	}
	widevineCenc, err := proto.Marshal(widevineCencHeader)
	if err != nil {
		return "", fmt.Errorf("failed to marshal WidevineCencHeader: %v", err)
	}
	//最前面添加32字节
	widevineCenc = append([]byte("0123456789abcdef0123456789abcdef"), widevineCenc...)
	pssh := base64.StdEncoding.EncodeToString(widevineCenc)
	return pssh, nil
}

func BeforeRequest(cl *resty.Client, ctx context.Context, url string, body []byte) (*resty.Response, error) {
	jsondata := map[string]interface{}{
		"challenge":      base64.StdEncoding.EncodeToString(body), // 'body' is passed in directly
		"key-system":     "com.widevine.alpha",
		"uri":            ctx.Value("uriPrefix").(string) + "," + ctx.Value("pssh").(string),
		"adamId":         ctx.Value("adamId").(string),
		"isLibrary":      false,
		"user-initiated": true,
	}

	resp, err := cl.R().
		SetContext(ctx).
		SetBody(jsondata).
		Post(url)

	if err != nil {
		fmt.Println(err)
	}

	return resp, err
}

func AfterRequest(response *resty.Response) ([]byte, error) {
	var responseData PlaybackLicense

	err := json.Unmarshal(response.Body(), &responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response JSON: %v", err)
	}

	if responseData.ErrorCode != 0 || responseData.Status != 0 {
		return nil, fmt.Errorf("error in license response, code: %d, status: %d", responseData.ErrorCode, responseData.Status)
	}

	license, err := base64.StdEncoding.DecodeString(responseData.License)
	if err != nil {
		return nil, fmt.Errorf("failed to decode license: %v", err)
	}

	return license, nil
}

func GetWebplayback(adamId string, authtoken string, mutoken string, mvmode bool) (string, string, string, error) {
	url := "https://play.music.apple.com/WebObjects/MZPlay.woa/wa/webPlayback"
	postData := map[string]string{
		"salableAdamId": adamId,
	}
	jsonData, err := json.Marshal(postData)
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
		return "", "", "", err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(jsonData)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://music.apple.com")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Referer", "https://music.apple.com/")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authtoken))
	req.Header.Set("x-apple-music-user-token", mutoken)
	// 创建 HTTP 客户端
	//client := &http.Client{}
	resp, err := http.DefaultClient.Do(req)
	// 发送请求
	//resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return "", "", "", err
	}
	defer resp.Body.Close()
	//fmt.Println("Response Status:", resp.Status)
	obj := new(Songlist)
	err = json.NewDecoder(resp.Body).Decode(&obj)
	if err != nil {
		fmt.Println("json err:", err)
		return "", "", "", err
	}
	if len(obj.List) > 0 {
		if mvmode {
			return obj.List[0].HlsPlaylistUrl, "", "", nil
		}
		// 遍历 Assets
		for i := range obj.List[0].Assets {
			if obj.List[0].Assets[i].Flavor == "28:ctrp256" {
				kidBase64, fileurl, uriPrefix, err := extractKidBase64(obj.List[0].Assets[i].URL, false)
				if err != nil {
					return "", "", "", err
				}
				return fileurl, kidBase64, uriPrefix, nil
			}
			continue
		}
	}
	return "", "", "", errors.New("Unavailable")
}

type Songlist struct {
	List []struct {
		Hlsurl         string `json:"hls-key-cert-url"`
		HlsPlaylistUrl string `json:"hls-playlist-url"`
		Assets         []struct {
			Flavor string `json:"flavor"`
			URL    string `json:"URL"`
		} `json:"assets"`
	} `json:"songList"`
	Status int `json:"status"`
}

func extractKidBase64(b string, mvmode bool) (string, string, string, error) {
	resp, err := http.Get(b)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", "", errors.New(resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", err
	}
	masterString := string(body)
	from, listType, err := m3u8.DecodeFrom(strings.NewReader(masterString), true)
	if err != nil {
		return "", "", "", err
	}
	var kidbase64 string
	var uriPrefix string
	var urlBuilder strings.Builder
	if listType == m3u8.MEDIA {
		mediaPlaylist := from.(*m3u8.MediaPlaylist)
		if mediaPlaylist.Key != nil {
			split := strings.Split(mediaPlaylist.Key.URI, ",")
			uriPrefix = split[0]
			kidbase64 = split[1]
			lastSlashIndex := strings.LastIndex(b, "/")
			// 截取最后一个斜杠之前的部分
			urlBuilder.WriteString(b[:lastSlashIndex])
			urlBuilder.WriteString("/")
			urlBuilder.WriteString(mediaPlaylist.Map.URI)
			//fileurl = b[:lastSlashIndex] + "/" + mediaPlaylist.Map.URI
			//fmt.Println("Extracted URI:", mediaPlaylist.Map.URI)
			if mvmode {
				for _, segment := range mediaPlaylist.Segments {
					if segment != nil {
						//fmt.Println("Extracted URI:", segment.URI)
						urlBuilder.WriteString(";")
						urlBuilder.WriteString(b[:lastSlashIndex])
						urlBuilder.WriteString("/")
						urlBuilder.WriteString(segment.URI)
						//fileurl = fileurl + ";" + b[:lastSlashIndex] + "/" + segment.URI
					}
				}
			}
		} else {
			fmt.Println("No key information found")
		}
	} else {
		fmt.Println("Not a media playlist")
	}
	return kidbase64, urlBuilder.String(), uriPrefix, nil
}
func extsong(b string) bytes.Buffer {
	resp, err := http.Get(b)
	if err != nil {
		fmt.Printf("下载文件失败: %v\n", err)
	}
	defer resp.Body.Close()
	var buffer bytes.Buffer
	bar := progressbar.NewOptions64(
		resp.ContentLength,
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
	io.Copy(io.MultiWriter(&buffer, bar), resp.Body)
	return buffer
}
func Run(adamId string, trackpath string, authtoken string, mutoken string, mvmode bool, serverUrl string) (string, error) {
	var keystr string //for mv key
	var fileurl string
	var kidBase64 string
	var uriPrefix string
	var err error
	if mvmode {
		kidBase64, fileurl, uriPrefix, err = extractKidBase64(trackpath, true)
		if err != nil {
			return "", err
		}
	} else {
		fileurl, kidBase64, uriPrefix, err = GetWebplayback(adamId, authtoken, mutoken, false)
		if err != nil {
			return "", err
		}
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "pssh", kidBase64)
	ctx = context.WithValue(ctx, "adamId", adamId)
	ctx = context.WithValue(ctx, "uriPrefix", uriPrefix)
	pssh, err := getPSSH("", kidBase64)
	//fmt.Println(pssh)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	headers := map[string]string{
		"authorization":            "Bearer " + authtoken,
		"x-apple-music-user-token": mutoken,
	}
	client := resty.New()
	client.SetHeaders(headers)
	key := key.Key{
		ReqCli:        client,
		BeforeRequest: BeforeRequest,
		AfterRequest:  AfterRequest,
	}
	key.CdmInit()
	var keybt []byte
	if serverUrl != "" {
		keystr, keybt, err = key.GetKey(ctx, serverUrl, pssh, nil)
		if err != nil {
			fmt.Println(err)
			return "", err
		}
	} else {
		keystr, keybt, err = key.GetKey(ctx, "https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/acquireWebPlaybackLicense", pssh, nil)
		if err != nil {
			fmt.Println(err)
			return "", err
		}
	}
	if mvmode {
		keyAndUrls := "1:" + keystr + ";" + fileurl
		return keyAndUrls, nil
	}
	body := extsong(fileurl)
	fmt.Print("Downloaded\n")
	//bodyReader := bytes.NewReader(body)
	var buffer bytes.Buffer

	err = DecryptMP4(&body, keybt, &buffer)
	if err != nil {
		fmt.Print("Decryption failed\n")
		return "", err
	} else {
		fmt.Print("Decrypted\n")
	}
	// create output file
	ofh, err := os.Create(trackpath)
	if err != nil {
		fmt.Printf("创建文件失败: %v\n", err)
		return "", err
	}
	defer ofh.Close()

	_, err = ofh.Write(buffer.Bytes())
	if err != nil {
		fmt.Printf("写入文件失败: %v\n", err)
		return "", err
	}
	return "", nil
}

// RunStream downloads the AAC track as a streaming HTTP GET and decrypts it
// fragment-by-fragment, writing each decrypted moof+mdat to w immediately.
// Optimisations:
//   - Widevine key is cached by KID — CDM round-trip skipped on repeat plays.
//   - HTTP GET and CDM handshake run in parallel; playback starts as soon as
//     both are ready (whichever finishes last is the only gate).
//   - 64 KB read-ahead so the first fragment is available to the pipe fast.
func RunStream(adamId string, authtoken string, mutoken string, w io.Writer) error {
	fileurl, kidBase64, uriPrefix, err := GetWebplayback(adamId, authtoken, mutoken, false)
	if err != nil {
		return err
	}

	// ── parallel: HTTP GET ────────────────────────────────────────────────────
	type httpResult struct {
		resp *http.Response
		err  error
	}
	httpCh := make(chan httpResult, 1)
	go func() {
		resp, err := http.Get(fileurl)
		httpCh <- httpResult{resp, err}
	}()

	// ── parallel: CDM key fetch (cache-first) ─────────────────────────────────
	type keyResult struct {
		keybt []byte
		err   error
	}
	keyCh := make(chan keyResult, 1)
	go func() {
		if cached, ok := kidKeyCache.Load(kidBase64); ok {
			fmt.Print("🔑 Key from cache\n")
			keyCh <- keyResult{keybt: cached.([]byte)}
			return
		}
		ctx := context.Background()
		ctx = context.WithValue(ctx, "pssh", kidBase64)
		ctx = context.WithValue(ctx, "adamId", adamId)
		ctx = context.WithValue(ctx, "uriPrefix", uriPrefix)
		pssh, err := getPSSH("", kidBase64)
		if err != nil {
			keyCh <- keyResult{err: err}
			return
		}
		headers := map[string]string{
			"authorization":            "Bearer " + authtoken,
			"x-apple-music-user-token": mutoken,
		}
		cl := resty.New()
		cl.SetHeaders(headers)
		k := key.Key{
			ReqCli:        cl,
			BeforeRequest: BeforeRequest,
			AfterRequest:  AfterRequest,
		}
		k.CdmInit()
		_, kb, err := k.GetKey(ctx, "https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/acquireWebPlaybackLicense", pssh, nil)
		if err != nil {
			keyCh <- keyResult{err: err}
			return
		}
		kidKeyCache.Store(kidBase64, kb)
		keyCh <- keyResult{keybt: kb}
	}()

	// ── wait for both ─────────────────────────────────────────────────────────
	hr := <-httpCh
	if hr.err != nil {
		return fmt.Errorf("stream GET failed: %w", hr.err)
	}
	defer hr.resp.Body.Close()

	kr := <-keyCh
	if kr.err != nil {
		return kr.err
	}
	keybt := kr.keybt

	r := bufio.NewReaderSize(hr.resp.Body, 64*1024) // 64 KB — first fragment arrives faster
	var offset uint64

	// Read init segment (ftyp + moov) box by box.
	init := mp4.NewMP4Init()
	for {
		box, err := mp4.DecodeBox(offset, r)
		if err != nil {
			return fmt.Errorf("reading init box: %w", err)
		}
		offset += box.Size()
		init.AddChild(box)
		if box.Type() == "moov" {
			break
		}
	}
	di, err := mp4.DecryptInit(init)
	if err != nil {
		return fmt.Errorf("DecryptInit: %w", err)
	}
	if err = init.Encode(w); err != nil {
		return fmt.Errorf("writing init: %w", err)
	}
	// Flush init segment immediately so the player can start parsing codec info.
	if fw, ok := w.(interface{ Flush() error }); ok {
		_ = fw.Flush()
	}

	// Stream fragments: read moof+mdat, decrypt, write, flush — one at a time.
	fragN := 0
	for {
		box, err := mp4.DecodeBox(offset, r)
		if err == io.EOF {
			fmt.Printf("\r🎵 Stream complete (%d fragments)\n", fragN)
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading fragment box: %w", err)
		}
		offset += box.Size()

		switch box.Type() {
		case "styp", "sidx", "prft", "emsg":
			// Pass through non-media boxes without decryption.
			if err = box.Encode(w); err != nil {
				return err
			}
		case "moof":
			moof, ok := box.(*mp4.MoofBox)
			if !ok {
				continue
			}
			// The mdat immediately follows moof in Apple's fMP4 layout.
			mdatBox, err := mp4.DecodeBox(offset, r)
			if err != nil {
				return fmt.Errorf("reading mdat: %w", err)
			}
			offset += mdatBox.Size()

			frag := mp4.NewFragment()
			frag.AddChild(moof)
			frag.AddChild(mdatBox)

			seg := mp4.NewMediaSegmentWithoutStyp()
			seg.AddFragment(frag)

			if err = mp4.DecryptSegment(seg, di, keybt); err != nil {
				if err.Error() == "no senc box in traf" {
					err = nil
				} else {
					return fmt.Errorf("DecryptSegment: %w", err)
				}
			}
			if err = seg.Encode(w); err != nil {
				return fmt.Errorf("writing segment: %w", err)
			}
			fragN++
			fmt.Printf("\r⚡ Fragment %d piped to player", fragN)
			// Flush after every fragment so the player receives data immediately.
			if fw, ok := w.(interface{ Flush() error }); ok {
				_ = fw.Flush()
			}
		}
	}
}
// No disk I/O is performed — the caller can pipe the buffer directly to a media player.
func RunToBuffer(adamId string, authtoken string, mutoken string) (*bytes.Buffer, error) {
	fileurl, kidBase64, uriPrefix, err := GetWebplayback(adamId, authtoken, mutoken, false)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "pssh", kidBase64)
	ctx = context.WithValue(ctx, "adamId", adamId)
	ctx = context.WithValue(ctx, "uriPrefix", uriPrefix)
	pssh, err := getPSSH("", kidBase64)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	headers := map[string]string{
		"authorization":            "Bearer " + authtoken,
		"x-apple-music-user-token": mutoken,
	}
	cl := resty.New()
	cl.SetHeaders(headers)
	k := key.Key{
		ReqCli:        cl,
		BeforeRequest: BeforeRequest,
		AfterRequest:  AfterRequest,
	}
	k.CdmInit()
	_, keybt, err := k.GetKey(ctx, "https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/acquireWebPlaybackLicense", pssh, nil)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	body := extsong(fileurl)
	var buffer bytes.Buffer
	if err = DecryptMP4(&body, keybt, &buffer); err != nil {
		fmt.Print("Decryption failed\n")
		return nil, err
	}
	fmt.Print("Decrypted\n")
	return &buffer, nil
}

// Segment 结构体用于在 Channel 中传递分段数据
type Segment struct {
	Index int
	Data  []byte
}

func downloadSegment(url string, index int, wg *sync.WaitGroup, segmentsChan chan<- Segment, client *http.Client, limiter chan struct{}) {
	// 函数退出时，从 limiter 中接收一个值，释放一个并发槽位
	defer func() {
		<-limiter
		wg.Done()
	}()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("错误(分段 %d): 创建请求失败: %v\n", index, err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("错误(分段 %d): 下载失败: %v\n", index, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("错误(分段 %d): 服务器返回状态码 %d\n", index, resp.StatusCode)
		return
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("错误(分段 %d): 读取数据失败: %v\n", index, err)
		return
	}

	// 将下载好的分段（包含序号和数据）发送到 Channel
	segmentsChan <- Segment{Index: index, Data: data}
}

// fileWriter 从 Channel 接收分段并按顺序写入文件
func fileWriter(wg *sync.WaitGroup, segmentsChan <-chan Segment, outputFile io.Writer, totalSegments int) {
	defer wg.Done()

	// 缓冲区，用于存放乱序到达的分段
	// key 是分段序号，value 是分段数据
	segmentBuffer := make(map[int][]byte)
	nextIndex := 0 // 期望写入的下一个分段的序号

	for segment := range segmentsChan {
		// 检查收到的分段是否是当前期望的
		if segment.Index == nextIndex {
			//fmt.Printf("写入分段 %d\n", segment.Index)
			_, err := outputFile.Write(segment.Data)
			if err != nil {
				fmt.Printf("错误(分段 %d): 写入文件失败: %v\n", segment.Index, err)
			}
			nextIndex++

			// 检查缓冲区中是否有下一个连续的分段
			for {
				data, ok := segmentBuffer[nextIndex]
				if !ok {
					break // 缓冲区里没有下一个，跳出循环，等待下一个分段到达
				}

				//fmt.Printf("从缓冲区写入分段 %d\n", nextIndex)
				_, err := outputFile.Write(data)
				if err != nil {
					fmt.Printf("错误(分段 %d): 从缓冲区写入文件失败: %v\n", nextIndex, err)
				}
				// 从缓冲区删除已写入的分段，释放内存
				delete(segmentBuffer, nextIndex)
				nextIndex++
			}
		} else {
			// 如果不是期望的分段，先存入缓冲区
			//fmt.Printf("缓冲分段 %d (等待 %d)\n", segment.Index, nextIndex)
			segmentBuffer[segment.Index] = segment.Data
		}
	}

	// 确保所有分段都已写入
	if nextIndex != totalSegments {
		fmt.Printf("警告: 写入完成，但似乎有分段丢失。期望 %d 个, 实际写入 %d 个。\n", totalSegments, nextIndex)
	}
}

func ExtMvData(keyAndUrls string, savePath string) error {
	segments := strings.Split(keyAndUrls, ";")
	key := segments[0]
	//fmt.Println(key)
	urls := segments[1:]
	tempFile, err := os.CreateTemp("", "enc_mv_data-*.mp4")
	if err != nil {
		fmt.Printf("创建文件失败：%v\n", err)
		return err
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	var downloadWg, writerWg sync.WaitGroup
	segmentsChan := make(chan Segment, len(urls))
	// --- 新增代码: 定义最大并发数 ---
	const maxConcurrency = 10
	// --- 新增代码: 创建带缓冲的 Channel 作为信号量 ---
	limiter := make(chan struct{}, maxConcurrency)
	client := &http.Client{}

	// 初始化进度条
	bar := progressbar.DefaultBytes(-1, "Downloading...")
	barWriter := io.MultiWriter(tempFile, bar)

	// 启动写入 Goroutine
	writerWg.Add(1)
	go fileWriter(&writerWg, segmentsChan, barWriter, len(urls))

	// 启动下载 Goroutines
	for i, url := range urls {
		// 在启动 Goroutine 前，向 limiter 发送一个值来“获取”一个槽位
		// 如果 limiter 已满 (达到10个)，这里会阻塞，直到有其他任务完成并释放槽位
		//fmt.Printf("请求启动任务 %d...\n", i)
		limiter <- struct{}{}
		//fmt.Printf("...任务 %d 已启动\n", i)

		downloadWg.Add(1)
		// 将 limiter 传递给下载函数
		go downloadSegment(url, i, &downloadWg, segmentsChan, client, limiter)
	}

	// 等待所有下载任务完成
	downloadWg.Wait()
	// 下载完成后，关闭 Channel。写入 Goroutine 会在处理完 Channel 中所有数据后退出。
	close(segmentsChan)

	// 等待写入 Goroutine 完成所有写入和缓冲处理
	writerWg.Wait()

	// 显式关闭文件（defer会再次调用，但重复关闭是安全的）
	if err := tempFile.Close(); err != nil {
		fmt.Printf("关闭临时文件失败: %v\n", err)
		return err
	}
	fmt.Println("\nDownloaded.")

	cmd1 := exec.Command("mp4decrypt", "--key", key, tempFile.Name(), filepath.Base(savePath))
	cmd1.Dir = filepath.Dir(savePath) //设置mp4decrypt的工作目录以解决中文路径错误
	outlog, err := cmd1.CombinedOutput()
	if err != nil {
		fmt.Printf("Decrypt failed: %v\n", err)
		fmt.Printf("Output:\n%s\n", outlog)
		return err
	} else {
		fmt.Println("Decrypted.")
	}
	return nil
}

// DecryptMP4 decrypts a fragmented MP4 file with keys from widevice license. Supports CENC and CBCS schemes.
func DecryptMP4(r io.Reader, key []byte, w io.Writer) error {
	// Initialization
	inMp4, err := mp4.DecodeFile(r)
	if err != nil {
		return fmt.Errorf("failed to decode file: %w", err)
	}
	if !inMp4.IsFragmented() {
		return errors.New("file is not fragmented")
	}
	// Handle init segment
	if inMp4.Init == nil {
		return errors.New("no init part of file")
	}
	decryptInfo, err := mp4.DecryptInit(inMp4.Init)
	if err != nil {
		return fmt.Errorf("failed to decrypt init: %w", err)
	}
	if err = inMp4.Init.Encode(w); err != nil {
		return fmt.Errorf("failed to write init: %w", err)
	}
	// Decode segments
	for _, seg := range inMp4.Segments {
		if err = mp4.DecryptSegment(seg, decryptInfo, key); err != nil {
			if err.Error() == "no senc box in traf" {
				// No SENC box, skip decryption for this segment as samples can have
				// unencrypted segments followed by encrypted segments. See:
				// https://github.com/iyear/gowidevine/pull/26#issuecomment-2385960551
				err = nil
			} else {
				return fmt.Errorf("failed to decrypt segment: %w", err)
			}
		}
		if err = seg.Encode(w); err != nil {
			return fmt.Errorf("failed to encode segment: %w", err)
		}
	}
	return nil
}
