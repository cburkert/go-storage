package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	port             = 8080
	baseDir          = "/tmp/gostorage/"
	blobDir          = "blobs"
	tokenLenBytes    = 32
	cookieName       = ".cookie"
	tokenHeaderField = "X-Qabel-Token"
)

type Token string

type Volume struct {
	Id          string `json:"public"`
	WriteToken  Token  `json:"token"`
	RevokeToken Token  `json:"revoke_token"`
}

type VolumeServerCookie struct {
	Id                string
	HashedWriteToken  string
	HashedRevokeToken string
	Salt              string
}

func createToken() (Token, error) {
	randomBytes := make([]byte, tokenLenBytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	return Token(base64.URLEncoding.EncodeToString(randomBytes)), nil
}

func parseToken(raw string) (Token, error) {
	// client does not expect 401 on syntactically invalid tokens
	//bytes, err := base64.URLEncoding.DecodeString(raw)
	//if err != nil || len(bytes) != tokenLenBytes {
	//return "", errors.New("Invalid token")
	//}
	if raw == "" {
		return "", errors.New("Token missing")
	}
	return Token(raw), nil
}

func (t Token) hash() string {
	// todo implement hashing
	return string(t)
}

func createVolume() (*Volume, error) {
	volume := &Volume{}
	rawId := make([]byte, 16)
	_, err := rand.Read(rawId)
	if err != nil {
		return nil, err
	}
	volume.Id = hex.EncodeToString(rawId)
	volume.WriteToken, err = createToken()
	if err != nil {
		return nil, err
	}
	volume.RevokeToken, err = createToken()
	if err != nil {
		return nil, err
	}
	err = os.MkdirAll(filepath.Join(baseDir, volume.Id, blobDir), 0700)
	if err != nil {
		return nil, err
	}
	err = volume.save()
	if err != nil {
		// clean up incomplete volume
		volume.delete()
		return nil, err
	}

	return volume, nil
}

func (vol *Volume) getServerCookie() (*VolumeServerCookie, error) {
	cookie := &VolumeServerCookie{
		Id:                vol.Id,
		HashedWriteToken:  vol.WriteToken.hash(),
		HashedRevokeToken: vol.RevokeToken.hash(),
	}

	return cookie, nil
}

func (vol *Volume) save() error {
	// hash tokens before saving
	hashedVolume, err := vol.getServerCookie()
	if err != nil {
		return err
	}
	b, err := json.Marshal(hashedVolume)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(baseDir, vol.Id, cookieName), b, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (vol *Volume) getBlobPath(blobName string) string {
	return filepath.Join(baseDir, vol.Id, blobDir, blobName)
}

func (vol *Volume) delete() error {
	err := os.RemoveAll(filepath.Join(baseDir, vol.Id))
	return err
}

func (vol *Volume) deleteBlob(blobName string) error {
	err := os.Remove(vol.getBlobPath(blobName))
	return err
}

func (vol *Volume) exists() bool {
	_, err := os.Stat(filepath.Join(baseDir, vol.Id))
	if err != nil {
		if os.IsNotExist(err) == false {
			log.Fatal(err)
		}
		return false
	}
	return true
}

func readServerCookie(id string) (*VolumeServerCookie, error) {
	cookie := &VolumeServerCookie{}
	bytes, err := ioutil.ReadFile(filepath.Join(baseDir, id, cookieName))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, cookie)
	if err != nil {
		return nil, err
	}
	return cookie, nil
}

func (cookie *VolumeServerCookie) verifyWriteToken(t Token) bool {
	return cookie.HashedWriteToken == t.hash()
}

func (cookie *VolumeServerCookie) verifyRevokeToken(t Token) bool {
	return cookie.HashedRevokeToken == t.hash()
}

func createHandler(w http.ResponseWriter, r *http.Request) {
	volume, err := createVolume()
	if err != nil {
		log.Fatal(err)
		http.Error(w, "Internal error while creating volume.", http.StatusInternalServerError)
		return
	}
	jsn, err := json.Marshal(volume)
	if err != nil {
		log.Fatal(err)
		http.Error(w, "Internal error while creating volume.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(jsn)
}

func handler(w http.ResponseWriter, r *http.Request) {
	cleanedPath := path.Clean(r.URL.Path)
	log.Println(r.Method + " " + cleanedPath)
	pathTokens := strings.Split(cleanedPath, "/")
	volume := Volume{}
	var blobName string

	// First token is empty because of heading slash
	switch len(pathTokens) {
	case 2:
		volume.Id = pathTokens[1]
	case 3:
		volume.Id = pathTokens[1]
		blobName = pathTokens[2]
	default:
		http.Error(w, "Invalid request path", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		if blobName == "" {
			if volume.exists() == true {
				http.Error(w, http.StatusText(http.StatusOK), http.StatusOK)
			} else {
				http.NotFound(w, r)
			}
			return
		}
		http.ServeFile(w, r, volume.getBlobPath(blobName))
	case "POST":
		if blobName == "" {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		token, err := parseToken(r.Header.Get(tokenHeaderField))
		if err != nil {
			http.Error(w, "Token required", http.StatusUnauthorized)
			return
		}
		cookie, err := readServerCookie(volume.Id)
		if err != nil {
			if os.IsNotExist(err) {
				http.NotFound(w, r)
				return
			} else {
				log.Fatal(err)
				http.Error(w, "Failed to read server cookie", http.StatusInternalServerError)
				return
			}
		}
		if cookie.verifyWriteToken(token) == false {
			http.Error(w, "Invalid token", http.StatusForbidden)
			return
		}
		// should we check body size?
		dst, err := os.Create(volume.getBlobPath(blobName))
		defer dst.Close()
		if err != nil {
			log.Fatal(err)
			http.Error(w, "Failed to write blob", http.StatusInternalServerError)
			return
		}

		_, err = io.Copy(dst, r.Body)
		if err != nil {
			log.Fatal(err)
			http.Error(w, "Failed to write blob", http.StatusInternalServerError)
			// clean up incompletely written blob
			volume.deleteBlob(blobName)
			return
		}
	case "DELETE":
		token, err := parseToken(r.Header.Get(tokenHeaderField))
		if err != nil {
			http.Error(w, "Token required", http.StatusUnauthorized)
			return
		}
		cookie, err := readServerCookie(volume.Id)
		if err != nil {
			if os.IsNotExist(err) {
				http.NotFound(w, r)
				return
			} else {
				log.Fatal(err)
				http.Error(w, "Failed to read server cookie", http.StatusInternalServerError)
				return
			}
		}
		if blobName != "" {
			// todo: doc says that write token should be submitted by client does not comply
			//if cookie.verifyWriteToken(token) == false {
			if cookie.verifyRevokeToken(token) == false {
				http.Error(w, "Invalid token", http.StatusForbidden)
				return
			}
			err = volume.deleteBlob(blobName)
			if err != nil {
				if os.IsNotExist(err) {
					http.NotFound(w, r)
					return
				} else {
					log.Fatal(err)
					http.Error(w, "Failed to read server cookie", http.StatusInternalServerError)
					return
				}
			}
		} else {
			if cookie.verifyRevokeToken(token) == false {
				http.Error(w, "Invalid token", http.StatusForbidden)
				return
			}
			err = volume.delete()
			if err != nil {
				log.Fatal(err)
				http.Error(w, "Failed to delete volume", http.StatusInternalServerError)
				return
			}
		}
		// use Error for convenience, though no error is reported here
		http.Error(w, "Deletion successful", http.StatusNoContent)
	default:
		log.Fatal("Unexpected request")
		http.Error(w, "Invalid request method", http.StatusBadRequest)
		return
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/_new", createHandler)
	http.ListenAndServe(":8080", nil)
}
