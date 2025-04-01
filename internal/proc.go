package internal

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	// At least number of fields per line in /proc/<pid>/mountinfo.
	expectedAtLeastNumFieldsPerMountInfo = 10
	defaultHostProcFS                    = "/proc"
	hostProcFS                           = "HOST_PROCFS"
)

// MountInfo represents a single line in /proc/<pid>/mountinfo.
type MountInfo struct {
	// Unique ID for the mount (maybe reused after umount).
	ID int
	// The ID of the parent mount (or of self for the root of this mount namespace's mount tree).
	ParentID int
	// The value of `st_dev` for files on this filesystem.
	MajorMinor string
	// The pathname of the directory in the filesystem which forms the root of this mount.
	Root string
	// Mount source, filesystem-specific information. e.g. device, tmpfs name.
	Source string
	// Mount point, the pathname of the mount point.
	MountPoint string
	// Optional fieds, zero or more fields of the form "tag[:value]".
	OptionalFields []string
	// The filesystem type in the form "type[.subtype]".
	FsType string
	// Per-mount options.
	MountOptions []string
	// Per-superblock options.
	SuperOptions []string
}

// ParseMountInfo parses /proc/xxx/mountinfo format
func ParseMountInfo(content []byte) ([]MountInfo, error) {
	var infos []MountInfo

	for _, line := range bytes.Split(content, []byte("\n")) {
		if len(line) == 0 {
			// the last split() item is empty string following the last \n
			continue
		}

		// See `man proc` for authoritative description of format of the file.
		fields := bytes.Fields(line)
		if len(fields) < expectedAtLeastNumFieldsPerMountInfo {
			return nil, fmt.Errorf("wrong number of fields in (expected at least %d, got %d): %s", expectedAtLeastNumFieldsPerMountInfo, len(fields), line)
		}
		id, err := strconv.Atoi(string(fields[0]))
		if err != nil {
			return nil, err
		}
		parentID, err := strconv.Atoi(string(fields[1]))
		if err != nil {
			return nil, err
		}
		info := MountInfo{
			ID:           id,
			ParentID:     parentID,
			MajorMinor:   string(fields[2]),
			Root:         string(fields[3]),
			MountPoint:   string(fields[4]),
			MountOptions: strings.Split(string(fields[5]), ","),
		}
		// All fields until "-" are "optional fields".string
		i := 6
		for ; i < len(fields) && string(fields[i]) != "-"; i++ {
			info.OptionalFields = append(info.OptionalFields, string(fields[i]))
		}
		// Parse the rest 3 fields.
		i++
		if len(fields)-i < 3 {
			return nil, fmt.Errorf("expect 3 fields in %s, got %d", line, len(fields)-i)
		}
		info.FsType = string(fields[i])
		info.Source = string(fields[i+1])
		info.SuperOptions = strings.Split(string(fields[i+2]), ",")
		infos = append(infos, info)
	}
	return infos, nil
}

func Self(suffix string) string {
	value := os.Getenv(hostProcFS)
	if value == "" {
		value = defaultHostProcFS
	}
	return path.Join(value, "self", suffix)
}

func SelfMountInfo() ([]MountInfo, error) {
	content, err := os.ReadFile(Self("mountinfo"))
	if err != nil {
		return nil, err
	}
	return ParseMountInfo(content)
}
