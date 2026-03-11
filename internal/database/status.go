// Copyright (c) 2025 Valentin Lobstein (Chocapikk) <balgogan@protonmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package database

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	nethttp "net/http"
	"os"
	"time"

	"github.com/Chocapikk/wpprobe/internal/file"
)


const releaseURL = "https://github.com/Chocapikk/wpprobe/releases/download/db/wordfence_vulnerabilities.json"

func CheckDatabaseStatus() (exists bool, outdated bool) {
	localPath, err := file.GetStoragePath("wordfence_vulnerabilities.json")
	if err != nil {
		return false, false
	}

	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		return false, false
	}

	localMD5, err := localFileMD5(localPath)
	if err != nil {
		return true, false
	}

	remoteMD5, err := remoteBlobMD5()
	if err != nil {
		return true, false
	}

	return true, localMD5 != remoteMD5
}

func localFileMD5(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func remoteBlobMD5() (string, error) {
	client := &nethttp.Client{Timeout: 5 * time.Second}

	req, err := nethttp.NewRequest("HEAD", releaseURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	md5Header := resp.Header.Get("x-ms-blob-content-md5")
	if md5Header == "" {
		return "", fmt.Errorf("no MD5 header in response")
	}
	return md5Header, nil
}
