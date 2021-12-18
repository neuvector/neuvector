package common

import "errors"

var (
	// ErrFilesystem occurs when a filesystem interaction fails.
	ErrFilesystem = errors.New("something went wrong when interacting with the fs")

	// ErrCouldNotDownload occurs when a download fails.
	ErrCouldNotDownload = errors.New("could not download requested resource")

	// ErrNotFound occurs when a resource could not be found.
	ErrNotFound = errors.New("the resource cannot be found")

	// ErrCouldNotParse is returned when a fetcher fails to parse the update data.
	ErrCouldNotParse = errors.New("updater/fetchers: could not parse")
)
