package filerotate

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type RotatableFile struct {
	sync.Mutex

	Directory string // file dir
	Path      string // file path

	creationTime time.Time

	file       *os.File
	rotateType RotateType
}

type RotateType string

const (
	ROTATE_HOURLY RotateType = "ROTATE_HOURLY"
	ROTATE_DAILY  RotateType = "ROTATE_DAILY"
)

func New(directory string, rotateType RotateType) (*RotatableFile, error) {
	file, filePath, ferr := newFile(directory, rotateType)
	if ferr != nil {
		return &RotatableFile{}, ferr
	}

	rotatableFile := RotatableFile{
		creationTime: time.Now().UTC(),
		Directory:    directory,
		Path:         filePath,
		file:         file,
	}

	go rotatableFile.RotateFile()

	return &rotatableFile, nil
}

func newFile(directory string, rotateType RotateType) (file *os.File, filePath string, Error error) {
	now := time.Now().UTC()
	fileName := ""

	switch rotateType {
	case ROTATE_HOURLY:
		fileName = now.Format(time.RFC3339)
	case ROTATE_DAILY:
		fallthrough
	default:
		fileName = now.Format("2006-01-02")
	}

	filePath = filepath.Join(directory, fmt.Sprintf("%s.txt", fileName))

	derr := os.MkdirAll(directory, 0755)
	if derr != nil {
		return nil, filePath, derr
	}

	file, ferr := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if ferr != nil {
		return nil, filePath, ferr
	}

	return file, filePath, nil
}

func (rotatableFile *RotatableFile) RotateFile() {
	for {
		rotateAt := rotatableFile.getNextRotation()

		log.Printf("Next Disk log rotation is in: %f Hours\n", rotateAt.Hours())

		<-time.After(rotateAt) // wait untill duration

		newFile, _, nfErr := newFile(rotatableFile.Directory, rotatableFile.rotateType)
		if nfErr != nil {
			log.Println("Error while creation new file for rotation: ", nfErr)
		}

		rotatableFile.Mutex.Lock()

		// switch to new file
		oldFile := rotatableFile.file
		rotatableFile.file = newFile

		rotatableFile.Mutex.Unlock()

		// sync and close old file
		oldFile.Sync()
		oldFile.Close()
	}
}

func (rotatableFile *RotatableFile) getNextRotation() time.Duration {
	now := time.Now().UTC()
	switch rotatableFile.rotateType {
	case ROTATE_HOURLY:
		return now.Add(time.Hour).Sub(now)
	case ROTATE_DAILY:
		fallthrough
	default:
		return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC).Sub(now) // time between now and midnight
	}
}

func (rotatableFile *RotatableFile) Write(b []byte) (n int, err error) {
	rotatableFile.Mutex.Lock()
	defer rotatableFile.Mutex.Unlock()
	return rotatableFile.file.Write(b)
}

func (rotatableFile *RotatableFile) Close() error {
	rotatableFile.Mutex.Lock()
	defer rotatableFile.Mutex.Unlock()

	return rotatableFile.file.Close()
}
