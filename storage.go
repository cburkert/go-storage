package storage

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"code.google.com/p/go.crypto/scrypt"
)

const (
	blobDir          = "blobs"
	tokenLenBytes    = 32
	saltLenBytes     = 32
	hashLenBytes     = 64
	cookieName       = ".cookie"
	tokenHeaderField = "X-Qabel-Token"
)

type storageServer struct {
	baseDir string
}

type Token string

type Volume struct {
	Id          string `json:"public"`
	WriteToken  Token  `json:"token"`
	RevokeToken Token  `json:"revoke_token"`
	salt        []byte
	server      *storageServer
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

func (t Token) hash(salt []byte) (string, error) {
	hash, err := scrypt.Key([]byte(t), salt, 1<<14, 8, 1, hashLenBytes)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (s *storageServer) createVolume() (*Volume, error) {
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
	volume.salt = make([]byte, saltLenBytes)
	_, err = rand.Read(volume.salt)
	if err != nil {
		return nil, err
	}

	err = os.MkdirAll(filepath.Join(s.baseDir, volume.Id, blobDir), 0700)
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
		Id: vol.Id,
	}
	var err error
	cookie.HashedWriteToken, err = vol.WriteToken.hash(vol.salt)
	if err != nil {
		return nil, err
	}
	cookie.HashedRevokeToken, err = vol.RevokeToken.hash(vol.salt)
	if err != nil {
		return nil, err
	}
	cookie.Salt = string(vol.salt)

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
	err = ioutil.WriteFile(filepath.Join(vol.server.baseDir, vol.Id, cookieName), b, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (vol *Volume) getBlobPath(blobName string) string {
	return filepath.Join(vol.server.baseDir, vol.Id, blobDir, blobName)
}

func (vol *Volume) delete() error {
	err := os.RemoveAll(filepath.Join(vol.server.baseDir, vol.Id))
	return err
}

func (vol *Volume) deleteBlob(blobName string) error {
	err := os.Remove(vol.getBlobPath(blobName))
	return err
}

func (vol *Volume) exists() bool {
	_, err := os.Stat(filepath.Join(vol.server.baseDir, vol.Id))
	if err != nil {
		if os.IsNotExist(err) == false {
			log.Fatal(err)
		}
		return false
	}
	return true
}

func (s *storageServer) readServerCookie(id string) (*VolumeServerCookie, error) {
	cookie := &VolumeServerCookie{}
	bytes, err := ioutil.ReadFile(filepath.Join(s.baseDir, id, cookieName))
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
	hash, err := t.hash([]byte(cookie.Salt))
	if err != nil {
		log.Print(err)
		return false
	}
	return cookie.HashedWriteToken == hash
}

func (cookie *VolumeServerCookie) verifyRevokeToken(t Token) bool {
	hash, err := t.hash([]byte(cookie.Salt))
	if err != nil {
		log.Print(err)
		return false
	}
	return cookie.HashedRevokeToken == hash
}
