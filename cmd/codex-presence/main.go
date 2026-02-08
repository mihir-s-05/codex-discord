package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const (
	defaultLargeImageKey    = "codex"
	defaultLargeImageText   = "Codex"
	defaultSmallImageKey    = "terminal"
	defaultSmallImageText   = "Windows"
	defaultOnSessionEnd     = "clear"
	defaultDebounceMs       = 100
	defaultLogLevel         = "INFO"
	staleRefreshMinutes     = 10
	daemonTickInterval      = 500 * time.Millisecond
	daemonIdleMinutes       = 30
	processStillActive      = 259
	defaultClientID         = "1465420195911831593"
	stateLockTimeout        = 2 * time.Second
	connectionCheckInterval = 30 * time.Second
	staleSessionTimeout     = 2 * time.Minute
)

const (
	opHandshake = int32(0)
	opFrame     = int32(1)
)

type Config struct {
	Discord  DiscordConfig  `json:"discord"`
	Privacy  PrivacyConfig  `json:"privacy"`
	Behavior BehaviorConfig `json:"behavior"`
	Logging  LoggingConfig  `json:"logging"`
}

type DiscordConfig struct {
	LargeImageKey  string `json:"largeImageKey"`
	LargeImageText string `json:"largeImageText"`
	SmallImageKey  string `json:"smallImageKey"`
	SmallImageText string `json:"smallImageText"`
}

type PrivacyConfig struct {
	ShowRepo     bool `json:"showRepo"`
	ShowBranch   bool `json:"showBranch"`
	ShowToolName bool `json:"showToolName"`
}

type BehaviorConfig struct {
	OnSessionEnd   string `json:"onSessionEnd"`
	UpdateDebounce int    `json:"updateDebounceMs"`
}

type LoggingConfig struct {
	Level string `json:"level"`
}

type ConfigOverrides struct {
	Discord  *DiscordOverrides  `json:"discord"`
	Privacy  *PrivacyOverrides  `json:"privacy"`
	Behavior *BehaviorOverrides `json:"behavior"`
	Logging  *LoggingOverrides  `json:"logging"`
}

type DiscordOverrides struct {
	LargeImageKey  *string `json:"largeImageKey"`
	LargeImageText *string `json:"largeImageText"`
	SmallImageKey  *string `json:"smallImageKey"`
	SmallImageText *string `json:"smallImageText"`
}

type PrivacyOverrides struct {
	ShowRepo     *bool `json:"showRepo"`
	ShowBranch   *bool `json:"showBranch"`
	ShowToolName *bool `json:"showToolName"`
}

type BehaviorOverrides struct {
	OnSessionEnd   *string `json:"onSessionEnd"`
	UpdateDebounce *int    `json:"updateDebounceMs"`
}

type LoggingOverrides struct {
	Level *string `json:"level"`
}

type State struct {
	Active           bool   `json:"active"`
	SessionID        string `json:"sessionId,omitempty"`
	StartTimestamp   int64  `json:"startTimestamp"`
	LastDetails      string `json:"lastDetails,omitempty"`
	LastState        string `json:"lastState,omitempty"`
	LastUpdatedMs    int64  `json:"lastUpdatedMs,omitempty"`
	DesiredDetails   string `json:"desiredDetails,omitempty"`
	DesiredState     string `json:"desiredState,omitempty"`
	DesiredUpdatedMs int64  `json:"desiredUpdatedMs,omitempty"`
	DaemonPid        int    `json:"daemonPid,omitempty"`
	DaemonStartedMs  int64  `json:"daemonStartedMs,omitempty"`
	StopDaemon       bool   `json:"stopDaemon,omitempty"`
	ClearRequested   bool   `json:"clearRequested,omitempty"`
}

type StateLock struct {
	file *os.File
}

type Logger struct {
	level int
	file  *os.File
}

type discordAssets struct {
	LargeImage string `json:"large_image,omitempty"`
	LargeText  string `json:"large_text,omitempty"`
	SmallImage string `json:"small_image,omitempty"`
	SmallText  string `json:"small_text,omitempty"`
}

type discordTimestamps struct {
	Start int64 `json:"start,omitempty"`
}

type discordActivity struct {
	Details    string             `json:"details,omitempty"`
	State      string             `json:"state,omitempty"`
	Assets     *discordAssets     `json:"assets,omitempty"`
	Timestamps *discordTimestamps `json:"timestamps,omitempty"`
	Instance   bool               `json:"instance"`
}

type discordCommand struct {
	Cmd   string                 `json:"cmd"`
	Args  map[string]interface{} `json:"args"`
	Nonce string                 `json:"nonce"`
}

type discordResponse struct {
	Cmd   string          `json:"cmd"`
	Evt   string          `json:"evt"`
	Data  json.RawMessage `json:"data"`
	Nonce string          `json:"nonce"`
}

type discordError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "set":
		setCmd(os.Args[2:])
	case "clear":
		clearCmd(os.Args[2:])
	case "diagnose":
		diagnoseCmd()
	case "daemon":
		daemonCmd(os.Args[2:])
	case "daemon-stop":
		daemonStopCmd()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "codex-presence.exe <command> [options]")
	fmt.Fprintln(os.Stderr, "Commands: set, clear, diagnose, daemon, daemon-stop")
}

func setCmd(args []string) {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	details := fs.String("details", "", "details text")
	state := fs.String("state", "", "state text")
	startTs := fs.Int64("start-ts", 0, "unix start timestamp")
	project := fs.String("project", "", "project path")
	debug := fs.Bool("debug", false, "print debug output")
	_ = fs.Parse(args)

	cfg, _, log := loadConfig(*project)
	defer log.Close()

	lock, err := acquireStateLock()
	if err != nil {
		log.Errorf("Failed to acquire state lock: %v", err)
		return
	}
	defer lock.Release()

	stateFile, ok := loadStateOnce()
	if !ok {
		stateFile = State{}
	}

	startTimestamp := determineStartTimestamp(stateFile, *startTs)
	nowMs := time.Now().UnixMilli()
	debounceMs := cfg.Behavior.UpdateDebounce
	if debounceMs <= 0 {
		debounceMs = defaultDebounceMs
	}

	stateFile.Active = true
	stateFile.StartTimestamp = startTimestamp
	stateFile.DesiredDetails = *details
	stateFile.DesiredState = *state
	stateFile.DesiredUpdatedMs = nowMs
	stateFile.ClearRequested = false
	stateFile.StopDaemon = false
	_ = saveState(stateFile)

	if !isDaemonRunning(stateFile) {
		if err := startDaemonDetached(*project, &stateFile); err != nil {
			log.Errorf("Failed to start daemon: %v", err)
			staleMs := int64(staleRefreshMinutes) * 60 * 1000
			if shouldSkipUpdate(stateFile, *details, *state, nowMs, debounceMs, staleMs) {
				log.Debugf("Skipping update due to debounce")
				return
			}
			if err := setActivity(cfg, *details, *state, startTimestamp, *debug, log); err != nil {
				log.Errorf("Failed to set activity: %v", err)
				return
			}
		} else {
			_ = saveState(stateFile)
		}
	}
}

func clearCmd(args []string) {
	fs := flag.NewFlagSet("clear", flag.ContinueOnError)
	project := fs.String("project", "", "project path")
	_ = fs.Parse(args)

	cfg, _, log := loadConfig(*project)
	defer log.Close()

	lock, err := acquireStateLock()
	if err != nil {
		log.Errorf("Failed to acquire state lock: %v", err)
		return
	}
	defer lock.Release()

	stateFile, ok := loadStateOnce()
	if !ok {
		stateFile = State{}
	}
	stateFile.ClearRequested = true
	stateFile.Active = false
	stateFile.DesiredDetails = ""
	stateFile.DesiredState = ""
	stateFile.DesiredUpdatedMs = time.Now().UnixMilli()
	_ = saveState(stateFile)

	if isDaemonRunning(stateFile) {
		log.Debugf("Daemon running; clear requested")
		return
	}

	if err := clearActivity(cfg, log); err != nil {
		log.Errorf("Failed to clear activity: %v", err)
		return
	}
	_ = clearState()
}

func diagnoseCmd() {
	_, paths, log := loadConfig("")
	defer log.Close()

	fmt.Println("Codex Presence Diagnostics")
	fmt.Println("-------------------------")
	fmt.Printf("OS: %s %s\n", runtime.GOOS, runtime.GOARCH)

	if paths.GlobalConfig != "" {
		fmt.Printf("Global config: %s\n", paths.GlobalConfig)
		if _, err := os.Stat(paths.GlobalConfig); err == nil {
			fmt.Println("Global config: found")
		} else {
			fmt.Println("Global config: missing")
		}
	}

	fmt.Printf("Discord Client ID: %s (hardcoded)\n", defaultClientID)

	if _, err := exec.LookPath("git"); err != nil {
		fmt.Println("Git: not found in PATH")
	} else {
		fmt.Println("Git: detected")
	}

	pipe, accessDenied, err := findDiscordPipe(250 * time.Millisecond)
	if err == nil {
		fmt.Printf("Discord IPC: found (%s)\n", pipe)
	} else if accessDenied {
		fmt.Printf("Discord IPC: permission denied (%v)\n", err)
		fmt.Println("Hint: run Discord and this helper at the same privilege level.")
	} else {
		fmt.Println("Discord IPC: not found")
	}
}

func daemonCmd(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	project := fs.String("project", "", "project path")
	run := fs.Bool("run", false, "internal")
	_ = fs.Parse(args)

	if *run {
		runDaemon(*project)
		return
	}

	stateFile, _ := loadState()
	if isDaemonRunning(stateFile) {
		return
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to determine executable path")
		return
	}

	cmdArgs := []string{"daemon", "--run"}
	if *project != "" {
		cmdArgs = append(cmdArgs, "--project", *project)
	}

	cmd := exec.Command(exe, cmdArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to start daemon:", err)
		return
	}
	_ = cmd.Process.Release()

	stateFile.DaemonPid = cmd.Process.Pid
	stateFile.DaemonStartedMs = time.Now().UnixMilli()
	stateFile.StopDaemon = false
	_ = saveState(stateFile)
}

func daemonStopCmd() {
	stateFile, lock, _ := loadStateWithLock()
	stateFile.StopDaemon = true
	stateFile.Active = false
	_ = saveStateWithLock(stateFile, lock)
}

func startDaemonDetached(projectPath string, stateFile *State) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	cmdArgs := []string{"daemon", "--run"}
	if strings.TrimSpace(projectPath) != "" {
		cmdArgs = append(cmdArgs, "--project", projectPath)
	}

	cmd := exec.Command(exe, cmdArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()

	if stateFile != nil {
		stateFile.DaemonPid = cmd.Process.Pid
		stateFile.DaemonStartedMs = time.Now().UnixMilli()
		stateFile.StopDaemon = false
	}
	return nil
}

func defaultConfig() Config {
	return Config{
		Discord: DiscordConfig{
			LargeImageKey:  defaultLargeImageKey,
			LargeImageText: defaultLargeImageText,
			SmallImageKey:  defaultSmallImageKey,
			SmallImageText: defaultSmallImageText,
		},
		Privacy: PrivacyConfig{
			ShowRepo:     true,
			ShowBranch:   true,
			ShowToolName: true,
		},
		Behavior: BehaviorConfig{
			OnSessionEnd:   defaultOnSessionEnd,
			UpdateDebounce: defaultDebounceMs,
		},
		Logging: LoggingConfig{
			Level: defaultLogLevel,
		},
	}
}

type configPaths struct {
	GlobalConfig  string
	ProjectConfig string
}

func loadConfig(projectPath string) (Config, configPaths, *Logger) {
	cfg := defaultConfig()
	paths := configPaths{}

	if globalPath := globalConfigPath(); globalPath != "" {
		paths.GlobalConfig = globalPath
		applyConfigFile(&cfg, globalPath)
	}

	if projectPath != "" {
		projectConfig := filepath.Join(projectPath, ".codex", "presence.json")
		paths.ProjectConfig = projectConfig
		applyConfigFile(&cfg, projectConfig)
	}

	logger := newLogger(cfg.Logging.Level)
	return cfg, paths, logger
}

func applyConfigFile(cfg *Config, path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var overrides ConfigOverrides
	if err := json.Unmarshal(content, &overrides); err != nil {
		return
	}

	applyOverrides(cfg, overrides)
}

func applyOverrides(cfg *Config, o ConfigOverrides) {
	if o.Discord != nil {
		if o.Discord.LargeImageKey != nil {
			cfg.Discord.LargeImageKey = *o.Discord.LargeImageKey
		}
		if o.Discord.LargeImageText != nil {
			cfg.Discord.LargeImageText = *o.Discord.LargeImageText
		}
		if o.Discord.SmallImageKey != nil {
			cfg.Discord.SmallImageKey = *o.Discord.SmallImageKey
		}
		if o.Discord.SmallImageText != nil {
			cfg.Discord.SmallImageText = *o.Discord.SmallImageText
		}
	}
	if o.Privacy != nil {
		if o.Privacy.ShowRepo != nil {
			cfg.Privacy.ShowRepo = *o.Privacy.ShowRepo
		}
		if o.Privacy.ShowBranch != nil {
			cfg.Privacy.ShowBranch = *o.Privacy.ShowBranch
		}
		if o.Privacy.ShowToolName != nil {
			cfg.Privacy.ShowToolName = *o.Privacy.ShowToolName
		}
	}
	if o.Behavior != nil {
		if o.Behavior.OnSessionEnd != nil {
			cfg.Behavior.OnSessionEnd = *o.Behavior.OnSessionEnd
		}
		if o.Behavior.UpdateDebounce != nil {
			cfg.Behavior.UpdateDebounce = *o.Behavior.UpdateDebounce
		}
	}
	if o.Logging != nil {
		if o.Logging.Level != nil {
			cfg.Logging.Level = *o.Logging.Level
		}
	}
}

func globalConfigPath() string {
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		return filepath.Join(appdata, "CodexPresence", "config.json")
	}
	if cfgDir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(cfgDir, "CodexPresence", "config.json")
	}
	return ""
}

func statePath() string {
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "CodexPresence", "state.json")
	}
	if cacheDir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(cacheDir, "CodexPresence", "state.json")
	}
	return "state.json"
}

func logsDir() string {
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "CodexPresence", "logs")
	}
	if cacheDir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(cacheDir, "CodexPresence", "logs")
	}
	return "logs"
}

func stateLockPath() string {
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "CodexPresence", "state.lock")
	}
	if cacheDir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(cacheDir, "CodexPresence", "state.lock")
	}
	return "state.lock"
}

func acquireStateLock() (*StateLock, error) {
	lockPath := stateLockPath()
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(stateLockTimeout)
	for {
		overlapped := &windows.Overlapped{}
		err := windows.LockFileEx(
			windows.Handle(file.Fd()),
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0,
			1,
			0,
			overlapped,
		)
		if err == nil {
			return &StateLock{file: file}, nil
		}

		if time.Now().After(deadline) {
			file.Close()
			return nil, fmt.Errorf("timeout acquiring state lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (l *StateLock) Release() {
	if l == nil || l.file == nil {
		return
	}
	overlapped := &windows.Overlapped{}
	_ = windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, overlapped)
	_ = l.file.Close()
}

func loadState() (State, bool) {
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		state, ok := loadStateOnce()
		if ok {
			return state, true
		}
		if attempt < maxAttempts-1 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	return State{}, false
}

func loadStateOnce() (State, bool) {
	path := statePath()
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, true
		}
		return State{}, false
	}
	var state State
	if err := json.Unmarshal(content, &state); err != nil {
		return State{}, false
	}
	return state, true
}

func loadStateWithLock() (State, *StateLock, bool) {
	lock, err := acquireStateLock()
	if err != nil {
		return State{}, nil, false
	}

	path := statePath()
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, lock, true
		}
		return State{}, lock, false
	}
	var state State
	if err := json.Unmarshal(content, &state); err != nil {
		return State{}, lock, false
	}
	return state, lock, true
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmpPath := filepath.Join(dir, fmt.Sprintf(".%s.tmp-%d-%d", base, os.Getpid(), time.Now().UnixNano()))

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	writeErr := func() error {
		if _, err := f.Write(data); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		return f.Close()
	}()
	if writeErr != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return writeErr
	}

	from, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err == nil {
		return nil
	}

	_ = os.Remove(path)
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func saveState(state State) error {
	path := statePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, content, 0o644)
}

func saveStateWithLock(state State, lock *StateLock) error {
	err := saveState(state)
	if lock != nil {
		lock.Release()
	}
	return err
}

func clearState() error {
	path := statePath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func clearStateWithLock() error {
	lock, _ := acquireStateLock()
	err := clearState()
	if lock != nil {
		lock.Release()
	}
	return err
}

func determineStartTimestamp(state State, startFlag int64) int64 {
	if startFlag > 0 {
		return startFlag
	}
	if state.Active && state.StartTimestamp > 0 {
		return state.StartTimestamp
	}
	return time.Now().Unix()
}

func shouldSkipUpdate(state State, details, status string, nowMs int64, debounceMs int, staleMs int64) bool {
	if !state.Active {
		return false
	}
	if state.LastDetails != details || state.LastState != status {
		return false
	}
	if state.LastUpdatedMs == 0 {
		return false
	}
	if nowMs-state.LastUpdatedMs > staleMs {
		return false
	}
	return nowMs-state.LastUpdatedMs < int64(debounceMs)
}

func isDaemonRunning(state State) bool {
	if state.DaemonPid <= 0 {
		return false
	}
	return isProcessRunningWithName(state.DaemonPid, "codex-presence.exe")
}

func isProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		return false
	}
	return code == processStillActive
}

func isProcessRunningWithName(pid int, expectedName string) bool {
	if pid <= 0 {
		return false
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)

	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		return false
	}
	if code != processStillActive {
		return false
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return false
	}

	expectedLower := strings.ToLower(expectedName)
	for {
		if int(entry.ProcessID) == pid {
			exe := windows.UTF16ToString(entry.ExeFile[:])
			return strings.ToLower(exe) == expectedLower
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return false
}

func setActivity(cfg Config, details, status string, startTs int64, debug bool, log *Logger) error {
	conn, err := connectDiscord(log)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := sendHandshake(conn, defaultClientID); err != nil {
		log.Warnf("Handshake response error: %v", err)
	}

	return sendActivityWithRetry(conn, cfg, details, status, startTs, debug, log)
}

func clearActivity(cfg Config, log *Logger) error {
	conn, err := connectDiscord(log)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := sendHandshake(conn, defaultClientID); err != nil {
		log.Warnf("Handshake response error: %v", err)
	}

	return sendClear(conn, false)
}

func connectDiscord(log *Logger) (net.Conn, error) {
	pipe, _, err := findDiscordPipe(500 * time.Millisecond)
	if err != nil {
		return nil, err
	}

	conn, err := winio.DialPipe(pipe, nil)
	if err != nil {
		return nil, err
	}

	log.Debugf("Connected to Discord IPC at %s", pipe)
	return conn, nil
}

func findDiscordPipe(timeout time.Duration) (string, bool, error) {
	var lastErr error
	accessDenied := false
	for i := 0; i < 10; i++ {
		pipe := fmt.Sprintf("\\\\.\\pipe\\discord-ipc-%d", i)
		conn, err := winio.DialPipe(pipe, &timeout)
		if err == nil {
			_ = conn.Close()
			return pipe, false, nil
		}
		if isAccessDenied(err) {
			accessDenied = true
			lastErr = err
			continue
		}
		lastErr = err
	}
	if accessDenied {
		return "", true, lastErr
	}
	if lastErr == nil {
		lastErr = errors.New("discord ipc not found")
	}
	return "", false, lastErr
}

func isAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "access is denied")
}

func sendHandshake(conn net.Conn, clientID string) error {
	payload := map[string]interface{}{"v": 1, "client_id": clientID}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := writeFrame(conn, opHandshake, data); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _, err = readFrame(conn)
	if err != nil {
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			return nil
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		return err
	}
	return nil
}

func buildActivity(cfg Config, details, status string, startTs int64) discordActivity {
	activity := discordActivity{
		Details:  strings.TrimSpace(details),
		State:    strings.TrimSpace(status),
		Instance: false,
	}

	assets := discordAssets{}
	if cfg.Discord.LargeImageKey != "" {
		assets.LargeImage = cfg.Discord.LargeImageKey
		assets.LargeText = cfg.Discord.LargeImageText
	}
	if cfg.Discord.SmallImageKey != "" {
		assets.SmallImage = cfg.Discord.SmallImageKey
		assets.SmallText = cfg.Discord.SmallImageText
	}
	if assets.LargeImage != "" || assets.SmallImage != "" {
		activity.Assets = &assets
	}

	if startTs > 0 {
		activity.Timestamps = &discordTimestamps{Start: startTs}
	}

	return activity
}

func sendActivity(conn net.Conn, activity discordActivity, debug bool) error {
	cmd := discordCommand{
		Cmd:   "SET_ACTIVITY",
		Args:  map[string]interface{}{"pid": os.Getpid(), "activity": activity},
		Nonce: newNonce(),
	}

	payload, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	if err := writeFrame(conn, opFrame, payload); err != nil {
		return err
	}

	resp, err := readDiscordResponse(conn, 750*time.Millisecond)
	if err != nil {
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			return nil
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		return err
	}
	if resp == nil {
		if debug {
			fmt.Fprintln(os.Stdout, "discord response: <none>")
		}
		return nil
	}
	if debug {
		pretty, _ := json.MarshalIndent(resp, "", "  ")
		if len(pretty) > 0 {
			fmt.Fprintln(os.Stdout, "discord response:")
			fmt.Fprintln(os.Stdout, string(pretty))
		}
	}
	if strings.EqualFold(resp.Evt, "ERROR") {
		var derr discordError
		_ = json.Unmarshal(resp.Data, &derr)
		if derr.Message != "" {
			return fmt.Errorf("discord error %d: %s", derr.Code, derr.Message)
		}
		return fmt.Errorf("discord error %d", derr.Code)
	}

	return nil
}

func sendClear(conn net.Conn, debug bool) error {
	cmd := discordCommand{
		Cmd:   "SET_ACTIVITY",
		Args:  map[string]interface{}{"pid": os.Getpid(), "activity": nil},
		Nonce: newNonce(),
	}
	payload, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	if err := writeFrame(conn, opFrame, payload); err != nil {
		return err
	}
	resp, err := readDiscordResponse(conn, 750*time.Millisecond)
	if err != nil {
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			return nil
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		return err
	}
	if debug && resp != nil {
		pretty, _ := json.MarshalIndent(resp, "", "  ")
		if len(pretty) > 0 {
			fmt.Fprintln(os.Stdout, "discord response:")
			fmt.Fprintln(os.Stdout, string(pretty))
		}
	}
	if resp == nil {
		return nil
	}
	if strings.EqualFold(resp.Evt, "ERROR") {
		var derr discordError
		_ = json.Unmarshal(resp.Data, &derr)
		if derr.Message != "" {
			return fmt.Errorf("discord error %d: %s", derr.Code, derr.Message)
		}
		return fmt.Errorf("discord error %d", derr.Code)
	}
	return nil
}

func sendActivityWithRetry(conn net.Conn, cfg Config, details, status string, startTs int64, debug bool, log *Logger) error {
	activity := buildActivity(cfg, details, status, startTs)
	if err := sendActivity(conn, activity, debug); err != nil {
		if activity.Assets != nil {
			log.Warnf("Set activity failed; retrying without assets: %v", err)
			activity.Assets = nil
			return sendActivity(conn, activity, debug)
		}
		return err
	}
	return nil
}

func readDiscordResponse(conn net.Conn, timeout time.Duration) (*discordResponse, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	_, payload, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	var resp discordResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func ensureDiscordConn(conn net.Conn, cfg Config, log *Logger) net.Conn {
	if conn != nil {
		return conn
	}
	newConn, err := connectDiscord(log)
	if err != nil {
		log.Debugf("Discord connect failed: %v", err)
		return nil
	}
	if err := sendHandshake(newConn, defaultClientID); err != nil {
		log.Debugf("Discord handshake failed: %v", err)
		_ = newConn.Close()
		return nil
	}
	return newConn
}

func writeFrame(w io.Writer, opcode int32, data []byte) error {
	payload := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint32(payload[0:4], uint32(opcode))
	binary.LittleEndian.PutUint32(payload[4:8], uint32(len(data)))
	copy(payload[8:], data)
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) (int32, []byte, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	opcode := int32(binary.LittleEndian.Uint32(header[0:4]))
	length := int32(binary.LittleEndian.Uint32(header[4:8]))
	if length < 0 {
		return opcode, nil, fmt.Errorf("invalid frame length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return opcode, nil, err
	}
	return opcode, payload, nil
}

func newNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func newLogger(level string) *Logger {
	logDir := logsDir()
	_ = os.MkdirAll(logDir, 0o755)
	filePath := filepath.Join(logDir, time.Now().Format("2006-01-02")+".log")
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return &Logger{level: parseLogLevel(level)}
	}
	return &Logger{level: parseLogLevel(level), file: file}
}

func parseLogLevel(level string) int {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "ERROR":
		return 0
	case "WARN", "WARNING":
		return 1
	case "INFO":
		return 2
	case "DEBUG":
		return 3
	default:
		return 2
	}
}

func (l *Logger) Close() {
	if l == nil || l.file == nil {
		return
	}
	_ = l.file.Close()
}

func (l *Logger) logf(level int, label, format string, args ...interface{}) {
	if l == nil || level > l.level {
		return
	}
	line := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	entry := fmt.Sprintf("%s [%s] %s\n", timestamp, label, line)
	if l.file != nil {
		_, _ = l.file.WriteString(entry)
	}
	if level <= 1 {
		_, _ = fmt.Fprint(os.Stderr, entry)
	}
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logf(0, "ERROR", format, args...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.logf(1, "WARN", format, args...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.logf(2, "INFO", format, args...)
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logf(3, "DEBUG", format, args...)
}

func runDaemon(projectPath string) {
	cfg, _, log := loadConfig(projectPath)
	defer log.Close()

	cleanupDaemon := func(conn net.Conn, clearPresence bool) {
		if conn != nil {
			if clearPresence {
				_ = sendClear(conn, false)
			}
			_ = conn.Close()
		}
		stateFile, lock, _ := loadStateWithLock()
		if stateFile.DaemonPid == os.Getpid() {
			stateFile.DaemonPid = 0
			stateFile.DaemonStartedMs = 0
		}
		stateFile.StopDaemon = false
		_ = saveStateWithLock(stateFile, lock)
	}

	ticker := time.NewTicker(daemonTickInterval)
	defer ticker.Stop()

	var conn net.Conn
	var lastConnCheck time.Time

	for range ticker.C {
		stateFile, ok := loadState()
		if !ok {
			log.Debugf("Failed to load state; retrying next tick")
			continue
		}

		if conn != nil && time.Since(lastConnCheck) > connectionCheckInterval {
			if err := conn.SetReadDeadline(time.Now()); err != nil {
				log.Debugf("Connection health check failed, reconnecting: %v", err)
				_ = conn.Close()
				conn = nil
			}
			lastConnCheck = time.Now()
		}

		stopRequested := stateFile.StopDaemon

		if stateFile.DaemonPid != os.Getpid() {
			stateFile.DaemonPid = os.Getpid()
			stateFile.DaemonStartedMs = time.Now().UnixMilli()
			_ = saveState(stateFile)
		}

		if stateFile.ClearRequested {
			conn = ensureDiscordConn(conn, cfg, log)
			if conn == nil {
				continue
			}
			lastConnCheck = time.Now()
			if err := sendClear(conn, false); err == nil {
				stateFile.ClearRequested = false
				stateFile.LastDetails = ""
				stateFile.LastState = ""
				stateFile.LastUpdatedMs = time.Now().UnixMilli()
				_ = saveState(stateFile)
				if stopRequested {
					log.Debugf("Stop signal received after clear, daemon exiting")
					cleanupDaemon(conn, false)
					return
				}
			} else {
				log.Debugf("Clear attempt failed: %v", err)
				_ = conn.Close()
				conn = nil
			}
			continue
		}

		if stateFile.DesiredDetails == "" && stateFile.DesiredState == "" {
			if stopRequested {
				log.Debugf("Stop signal received, daemon exiting")
				cleanupDaemon(conn, true)
				return
			}
			if stateFile.DesiredUpdatedMs > 0 {
				idleFor := time.Since(time.UnixMilli(stateFile.DesiredUpdatedMs))
				if idleFor > time.Duration(daemonIdleMinutes)*time.Minute {
					log.Debugf("Idle timeout reached, daemon exiting")
					cleanupDaemon(conn, true)
					return
				}
			}
			continue
		}

		if stateFile.StartTimestamp == 0 {
			stateFile.StartTimestamp = time.Now().Unix()
			_ = saveState(stateFile)
		}

		conn = ensureDiscordConn(conn, cfg, log)
		if conn == nil {
			continue
		}
		lastConnCheck = time.Now()

		nowMs := time.Now().UnixMilli()

		// Safety net: if watcher hasn't sent an update in staleSessionTimeout,
		// it likely crashed or exited — clear the ghost presence
		if stateFile.DesiredUpdatedMs > 0 && nowMs-stateFile.DesiredUpdatedMs > staleSessionTimeout.Milliseconds() {
			log.Debugf("Desired state stale for %d ms, clearing presence", nowMs-stateFile.DesiredUpdatedMs)
			if err := sendClear(conn, false); err == nil {
				stateFile.Active = false
				stateFile.DesiredDetails = ""
				stateFile.DesiredState = ""
				stateFile.LastDetails = ""
				stateFile.LastState = ""
				stateFile.LastUpdatedMs = nowMs
				_ = saveState(stateFile)
			} else {
				log.Debugf("Stale clear failed: %v", err)
				_ = conn.Close()
				conn = nil
			}
			continue
		}

		staleMs := int64(staleRefreshMinutes) * 60 * 1000
		debounceMs := cfg.Behavior.UpdateDebounce
		if debounceMs <= 0 {
			debounceMs = defaultDebounceMs
		}

		if shouldSkipUpdate(stateFile, stateFile.DesiredDetails, stateFile.DesiredState, nowMs, debounceMs, staleMs) {
			continue
		}

		err := sendActivityWithRetry(conn, cfg, stateFile.DesiredDetails, stateFile.DesiredState, stateFile.StartTimestamp, false, log)
		if err != nil {
			log.Debugf("Daemon set failed: %v", err)
			_ = conn.Close()
			conn = nil
			continue
		}

		stateFile.LastDetails = stateFile.DesiredDetails
		stateFile.LastState = stateFile.DesiredState
		stateFile.LastUpdatedMs = nowMs
		_ = saveState(stateFile)
		if stopRequested {
			log.Debugf("Stop signal received after update, daemon exiting")
			cleanupDaemon(conn, true)
			return
		}
	}
}
