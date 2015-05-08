package storage

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
)

type storageHandler struct {
	serverMux     *http.ServeMux
	storageServer *storageServer
}

type creationHandler struct {
	storageHander *storageHandler
}

func (h *creationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	volume, err := h.storageHander.storageServer.createVolume()
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

type defaultHandler struct {
	storageHander *storageHandler
}

func (h *defaultHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cleanedPath := path.Clean(r.URL.Path)
	log.Println(r.Method + " " + cleanedPath)
	pathTokens := strings.Split(cleanedPath, "/")
	volume := Volume{server: h.storageHander.storageServer}
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
		cookie, err := h.storageHander.storageServer.readServerCookie(volume.Id)
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
		cookie, err := h.storageHander.storageServer.readServerCookie(volume.Id)
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

func (h *storageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.serverMux.ServeHTTP(w, r)
}

func StorageServer(baseDir string) http.Handler {
	h := &storageHandler{
		storageServer: &storageServer{baseDir},
	}
	serverMux := http.NewServeMux()
	serverMux.Handle("/", &defaultHandler{h})
	serverMux.Handle("/_new", &creationHandler{h})
	h.serverMux = serverMux
	return h
}
