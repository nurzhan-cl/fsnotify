package fsnotify

import "C"
import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cloudlinux/fsnotify/internal"
	"golang.org/x/sys/unix"
)

var (
	ErrInvalidFsid = errors.New("mount does not support FAN_REPORT_FID")
)

type fanotifyEventInfoHeader struct {
	InfoType uint8
	Pad      uint8
	Len      uint16
}

// fanotifyEventInfoFID represents fanotify_event_info_fid structure (see fanotify man page)
type fanotifyEventInfoFID struct {
	Hdr  fanotifyEventInfoHeader
	Fsid unix.Fsid
	// FileHandle starts here
}

type fsidMap struct {
	m  map[unix.Fsid]string
	mu sync.RWMutex
}

const (
	sizeOfFileHandleHdr        = C.sizeof_uint + C.sizeof_int
	sizeOfFanotifyEventInfoFID = (int)(unsafe.Sizeof(fanotifyEventInfoFID{}))
)

var (
	zeroFsid = unix.Fsid{Val: [2]int32{0, 0}}
)

func (f *fanotifyEventInfoFID) GetHandle(n int) (unix.FileHandle, error) {
	fid := f
	// Get pointer to the start of FileHandle
	fileHandlePtr := unsafe.Pointer(uintptr(unsafe.Pointer(fid)) + unsafe.Sizeof(*fid))

	// Check if hdr len exceeds n or has insufficient length
	if int(fid.Hdr.Len) > n || int(fid.Hdr.Len) < sizeOfFanotifyEventInfoFID+sizeOfFileHandleHdr {
		return unix.FileHandle{}, fmt.Errorf(
			"GetHandle: out of bounds. Expected size n: %v, fid.Hdr.Len: %v",
			n,
			fid.Hdr.Len,
		)
	}
	// The length of the buffer can be calculated from the Header's Len field
	// Subtract the size of the header to get the FileHandle buffer length
	bufferLen := int(fid.Hdr.Len) - sizeOfFanotifyEventInfoFID
	// Create a slice from the pointer
	buf := unsafe.Slice((*byte)(fileHandlePtr), bufferLen)

	// Get size and type of file_handle
	size := uint(*(*C.uint)(unsafe.Pointer(&buf[0])))
	typ := int32(*(*C.int)(unsafe.Pointer(&buf[C.sizeof_uint])))

	// Check if file_handle size is in bounds of n
	bufferLen = sizeOfFanotifyEventInfoFID + sizeOfFileHandleHdr + int(size)
	if bufferLen > n {
		return unix.FileHandle{}, fmt.Errorf(
			"GetHandle: out of bounds. Expected size: %v, actual size: %v",
			n,
			bufferLen,
		)
	}

	return unix.NewFileHandle(typ, buf[sizeOfFileHandleHdr:sizeOfFileHandleHdr+int(size)]), nil
}

func getPathFromHandle(mountFd int, handle unix.FileHandle) (string, error) {
	fd, err := unix.OpenByHandleAt(mountFd, handle, unix.O_PATH)
	if err != nil {
		return "", fmt.Errorf("open_by_handle_at failed: %v", err)
	}
	defer unix.Close(fd)

	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	path := make([]byte, unix.PathMax)

	n, err := unix.Readlink(procPath, path)
	if err != nil {
		return "", fmt.Errorf("readlink failed: %v", err)
	}

	return string(path[:n]), nil
}

func (fm *fsidMap) set(fsid unix.Fsid, mountPoint string) {
	fm.mu.Lock()
	v, ok := fm.m[fsid]
	if !ok || (ok && v != mountPoint) {
		fm.m[fsid] = mountPoint
	}
	fm.mu.Unlock()
}

func (fm *fsidMap) get(fsid unix.Fsid) (string, bool) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	v, ok := fm.m[fsid]
	return v, ok
}

func (fm *fsidMap) remove(fsid unix.Fsid) {
	fm.mu.Lock()
	if _, ok := fm.m[fsid]; ok {
		delete(fm.m, fsid)
	}
	fm.mu.Unlock()
}

type FanotifyWatcher struct {
	Fd              int
	done            chan struct{} // Channel for sending a "quit message" to the reader goroutine
	doneResp        chan struct{} // Channel to respond to Close
	isWatching      atomic.Bool
	Events          chan Event
	Errors          chan error
	poller          *FdPoller
	initFlags       uint
	initEventFFlags uint
	addMask         uint64
	addFlags        uint

	fm                   *fsidMap
	refreshFsidMapPeriod time.Duration
}

func (fw *FanotifyWatcher) refreshFsidMap() {
	mountInfo, err := internal.SelfMountInfo()
	if err != nil {
		select {
		case fw.Errors <- fmt.Errorf("failed to query self mountinfo: %w", err):
		case <-fw.done:
			return
		}
	}

	for _, mi := range mountInfo {
		var (
			statfs     unix.Statfs_t
			mountPoint string = mi.MountPoint
		)
		err := unix.Statfs(mountPoint, &statfs)
		if err != nil || statfs.Fsid == zeroFsid {
			continue
		}
		fw.fm.set(statfs.Fsid, mountPoint)
	}
}

func NewFanotifyWatcher(flags uint, eventFFlags uint, addMask uint64,
	addFlags uint, fsidMapRefreshPeriod time.Duration) (*FanotifyWatcher, error) {

	fd, err := unix.FanotifyInit(flags, eventFFlags)
	if fd < 0 {
		return nil, err
	}

	poller, err := NewFdPoller(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	fw := &FanotifyWatcher{
		Fd:              fd,
		done:            make(chan struct{}),
		doneResp:        make(chan struct{}),
		Events:          make(chan Event),
		Errors:          make(chan error),
		poller:          poller,
		initFlags:       flags,
		initEventFFlags: eventFFlags,
		addFlags:        addFlags,
		addMask:         addMask,
		fm: &fsidMap{
			mu: sync.RWMutex{},
			m:  make(map[unix.Fsid]string),
		},
	}
	go fw.readEvents()
	if fsidMapRefreshPeriod > 0 {
		go func() {
			ticker := time.NewTicker(fsidMapRefreshPeriod)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					fw.refreshFsidMap()
				case <-fw.done:
					return
				}
			}
		}()
	}
	return fw, nil
}

func (fw *FanotifyWatcher) Add(path string) error {
	if fw.initFlags&unix.FAN_REPORT_FID == unix.FAN_REPORT_FID {
		var statfs unix.Statfs_t
		err := unix.Statfs(path, &statfs)
		if err != nil {
			return fmt.Errorf("failed to statfs %s: %w", path, err)
		}
		if statfs.Fsid == zeroFsid {
			return fmt.Errorf("%s: %w", path, ErrInvalidFsid)
		}
		fw.fm.set(statfs.Fsid, path)
	}
	err := unix.FanotifyMark(
		fw.Fd,
		unix.FAN_MARK_ADD|fw.addFlags,
		fw.addMask,
		unix.AT_FDCWD,
		path,
	)
	if err != nil {
		log.Printf("unix.FanotifyMark(%d, flags=%s|%d, mask=%d, AT_FDCWD, %s) failed: %s\n",
			fw.Fd, "FAN_MARK_ADD", fw.addFlags, fw.addMask, path, err.Error())
		return err
	}

	return nil
}

func (fw *FanotifyWatcher) Remove(path string) error {
	if fw.isClosed() {
		return nil
	}

	if fw.initFlags&unix.FAN_REPORT_FID == unix.FAN_REPORT_FID {
		var statfs unix.Statfs_t
		err := unix.Statfs(path, &statfs)
		if err != nil {
			return fmt.Errorf("failed to statfs %s: %w", path, err)
		}
		if statfs.Fsid == zeroFsid {
			return fmt.Errorf("%s: %w", path, ErrInvalidFsid)
		}

		fw.fm.remove(statfs.Fsid)
	}

	if err := unix.FanotifyMark(fw.Fd, unix.FAN_MARK_REMOVE, fw.addMask, -1, path); err != nil {
		return err
	}
	return nil
}

func (fw *FanotifyWatcher) readEvents() {
	var (
		buf   [unix.FAN_EVENT_METADATA_LEN * 4096]byte // Buffer for a maximum of 4096 raw events
		n     int                                      // Number of bytes read with read()
		errno error                                    // Syscall errno
		ok    bool                                     // For poller.wait
	)

	defer close(fw.doneResp)
	defer close(fw.Errors)
	defer close(fw.Events)
	defer unix.Close(fw.Fd)
	defer fw.poller.Close()
	fw.isWatching.Store(true)

	for {
		// See if we have been closed.
		if fw.isClosed() {
			return
		}

		ok, errno = fw.poller.Wait()
		if errno != nil {
			select {
			case fw.Errors <- errno:
			case <-fw.done:
				return
			}
			continue
		}

		if !ok {
			continue
		}

		n, errno = unix.Read(fw.Fd, buf[:])
		// If a signal interrupted execution, see if we've been asked to close, and try again.
		// http://man7.org/linux/man-pages/man7/signal.7.html :
		if errno == unix.EINTR {
			continue
		}

		// unix.Read might have been woken up by Close. If so, we're done.
		if fw.isClosed() {
			return
		}

		if n < unix.FAN_EVENT_METADATA_LEN {
			var err error
			if n == 0 {
				// If EOF is received. This should really never happen.
				err = io.EOF
			} else if n < 0 {
				// If an error occurred while reading.
				err = errno
			} else {
				// Read was too short.
				err = errors.New("notify: short read in readEvents()")
			}
			select {
			case fw.Errors <- err:
			case <-fw.done:
				return
			}
			continue
		}

		var offset uint32
		for offset <= uint32(n-unix.FAN_EVENT_METADATA_LEN) {
			raw := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			if !(raw.Event_len >= unix.FAN_EVENT_METADATA_LEN && raw.Event_len <= uint32(n)-offset) {
				continue
			}

			mask := raw.Mask
			if mask&unix.FAN_Q_OVERFLOW != 0 {
				select {
				case fw.Errors <- ErrEventOverflow:
				case <-fw.done:
					return
				}
			}

			// Check if filehandles are supported (>5.1)
			if raw.Fd == unix.FAN_NOFD {
				fileHandleOffset := int(offset) + int(raw.Metadata_len)

				// advance offset to the next event in the event buffer to prepare for the next read
				offset += raw.Event_len

				// Check if filehandle event info FID is in bounds of the fanotify event
				if int(raw.Metadata_len)+sizeOfFanotifyEventInfoFID > int(raw.Event_len) {
					continue
				}
				// Get FID info
				info := (*fanotifyEventInfoFID)(unsafe.Pointer(&buf[fileHandleOffset]))
				if info.Hdr.InfoType == unix.FAN_EVENT_INFO_TYPE_FID {
					handle, err := info.GetHandle(int(raw.Event_len) - int(raw.Metadata_len))
					if err != nil {
						select {
						case fw.Errors <- err:
						case <-fw.done:
							return
						}
						continue
					}

					// get mount fd to supply into unix.OpenHandleAt from fsidMap
					mountPoint, ok := fw.fm.get(info.Fsid)
					if !ok {
						continue
					}
					mount, err := os.Open(mountPoint)
					if err != nil {
						mount.Close()
						select {
						case fw.Errors <- err:
							continue
						case <-fw.done:
							return
						}
					}
					path, err := getPathFromHandle(int(mount.Fd()), handle)
					mount.Close()
					if err != nil {
						if !errors.Is(err, unix.ESTALE) {
							select {
							case fw.Errors <- err:
							case <-fw.done:
								return
							}
						}
					} else {
						fw.Events <- newFanotifyFIDEvent(path, mask)
					}
				}
			} else {
				path, errno := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", raw.Fd))
				if errno != nil {
					select {
					case fw.Errors <- errno:
					case <-fw.done:
						return
					}
				}

				fw.Events <- newFanotifyEvent(path, uintptr(raw.Fd))
				offset += raw.Event_len
			}
		}
	}
}

func (fw *FanotifyWatcher) isClosed() bool {
	select {
	case <-fw.done:
		return true
	default:
		return false
	}
}

func newFanotifyEvent(name string, fd uintptr) Event {
	return Event{Name: name, Op: Write, File: os.NewFile(fd, name)}
}

func newFanotifyFIDEvent(name string, mask uint64) Event {
	e := Event{Name: name, File: nil}
	if mask&unix.FAN_MODIFY == unix.FAN_MODIFY || mask&unix.FAN_CLOSE_WRITE == unix.FAN_CLOSE_WRITE {
		e.Op |= Write
	}
	if mask&unix.FAN_MOVE_SELF == unix.FAN_MOVE_SELF || mask&unix.FAN_MOVE == unix.FAN_MOVE ||
		mask&unix.FAN_MOVED_TO == unix.FAN_MOVED_TO || mask&unix.FAN_MOVED_FROM == unix.FAN_MOVED_FROM {
		e.Op |= Move
	}
	return e
}

func (fw *FanotifyWatcher) Close() error {
	if fw.isClosed() {
		return nil
	}

	// Send 'close' signal to goroutine, and set the Watcher to closed.
	close(fw.done)

	// Wake up goroutine
	_ = fw.poller.Wake()

	// Wait for goroutine to close
	if fw.isWatching.Load() == true {
		<-fw.doneResp
	}

	return nil
}
