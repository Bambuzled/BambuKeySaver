#!/usr/bin/env bash
#
# Capture Bambu Studio's startup cert-API request with TLS decryption.
#
# Sets SSLKEYLOGFILE, starts a dumpcap capture, launches Bambu Studio -- the
# AppImage on Linux, the .app bundle on macOS -- (which makes the cert request
# on every startup), watches the traffic
# live with a second tshark that decrypts using the key log as it fills, and
# stops everything once the cert request is seen.  The TLS secrets are then
# injected into the capture with editcap so it is decryptable in Wireshark.
#
# All output lands in the current directory:
#     <base>-keys.log               the TLS key log
#     <base>.pcapng                 the raw capture
#     <base>-decrypted.pcapng       the capture with secrets embedded
#     <base>-trigger-url.txt        the URL of the request that matched the
#                                   trigger
#     <base>-trigger-response.json  the body of the response to the request
#                                   that matched the trigger
#
# The response JSON feeds straight into bambu-api-decrypt.py.
#
# Linux / macOS counterpart of Capture-BambuCert.ps1.

set -uo pipefail

if (( BASH_VERSINFO[0] >= 4 )); then
    mon_timeout=0.5; key_timeout=0.01
else
    mon_timeout=1;   key_timeout=1
fi

os=$(uname -s)

readonly DEFAULT_TRIGGER='(http.host == "api.bambulab.com" and http.request.uri contains "/v1/iot-service/api/user/applications/") or (http2.headers.authority == "api.bambulab.com" and http2.headers.path contains "/v1/iot-service/api/user/applications/")'

appimage=''
interface=''
seconds=60
capture_filter='tcp port 443'
trigger_filter=$DEFAULT_TRIGGER
grace=5
basename_arg=''
close_studio=0
list_interfaces=0

usage() {
    cat <<EOF
usage: ${0##*/} [options] /path/to/Bambu_Studio.AppImage        (Linux)
       ${0##*/} [options] /path/to/BambuStudio.app              (macOS, default /Applications/BambuStudio.app)

  -i, --interface NAME   capture interface (default: the default route's)
  -s, --seconds N        capture window, the backstop if the trigger never
                         fires (default: $seconds)
  -f, --filter BPF       capture filter (default: '$capture_filter', '' = all)
  -t, --trigger FILTER   Wireshark display filter that stops the capture once
                         it matches the live decrypted stream ('' = no monitor)
  -g, --grace N          keep capturing N seconds after the trigger matches,
                         so the response lands in the pcap (default: $grace)
  -b, --basename NAME    output file prefix (default: bambu-<timestamp>)
  -c, --close            close Bambu Studio even if the trigger never fires
                         (a trigger match always closes it)
  -L, --list-interfaces  print the capture interfaces and exit
  -h, --help             this text

examples:
  ${0##*/} ~/Downloads/Bambu_Studio_ubuntu-24.04.AppImage
  ${0##*/} /Applications/BambuStudio.app
  ${0##*/} -s 90 -g 10 ~/Bambu.AppImage
  ${0##*/} -t 'http.request.uri contains "app_cert"' ~/Bambu.AppImage
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
warn() { printf 'warning: %s\n' "$*" >&2; }

while (( $# )); do
    case $1 in
        -i|--interface)       interface=${2-}; shift 2 || die "$1 needs a value" ;;
        -s|--seconds)         seconds=${2-}; shift 2 || die "$1 needs a value" ;;
        -f|--filter)          capture_filter=${2-}; shift 2 || die "$1 needs a value" ;;
        -t|--trigger)         trigger_filter=${2-}; shift 2 || die "$1 needs a value" ;;
        -g|--grace)           grace=${2-}; shift 2 || die "$1 needs a value" ;;
        -b|--basename)        basename_arg=${2-}; shift 2 || die "$1 needs a value" ;;
        -c|--close)           close_studio=1; shift ;;
        -L|--list-interfaces) list_interfaces=1; shift ;;
        -h|--help)            usage; exit 0 ;;
        --)                   shift; break ;;
        -*)                   die "unknown option: $1" ;;
        *)                    [[ -n $appimage ]] && die "unexpected argument: $1"
                              appimage=$1; shift ;;
    esac
done
[[ $# -gt 0 && -z $appimage ]] && appimage=$1

if [[ $os == Darwin ]]; then
    # Wireshark.app's CLI tools are only on PATH if its installer added them.
    for d in /Applications/Wireshark.app/Contents/MacOS "$HOME/Applications/Wireshark.app/Contents/MacOS"; do
        [[ -x $d/dumpcap ]] && PATH=$PATH:$d
    done
    wireshark_hint='Install Wireshark (https://www.wireshark.org or `brew install --cask wireshark`), including ChmodBPF.'
else
    wireshark_hint='Install Wireshark (wireshark-common / wireshark-cli).'
fi
for tool in dumpcap editcap tshark; do
    command -v "$tool" >/dev/null || die "$tool not found. $wireshark_hint"
done
for tool in pgrep ps; do
    command -v "$tool" >/dev/null || die "$tool not found (procps)."
done
# setsid(1) is util-linux only; perl can do the same on macOS.
if command -v setsid >/dev/null; then
    new_session() { setsid "$@"; }
elif command -v perl >/dev/null; then
    new_session() { perl -MPOSIX -e 'POSIX::setsid(); exec @ARGV or die "exec: $!\n"' "$@"; }
else
    die "need setsid (util-linux) or perl to launch Bambu Studio in its own session"
fi

# BSD stat on macOS, GNU stat on Linux.
if [[ $os == Darwin ]]; then
    file_size() { stat -f %z -- "$1"; }
else
    file_size() { stat -c %s -- "$1"; }
fi

[[ $seconds =~ ^[0-9]+$ ]] || die "--seconds must be a whole number: $seconds"
[[ $grace   =~ ^[0-9]+$ ]] || die "--grace must be a whole number: $grace"

if (( list_interfaces )); then dumpcap -D; exit 0; fi

if [[ $os == Darwin ]]; then
    : "${appimage:=/Applications/BambuStudio.app}"
    appimage=${appimage%/}
    [[ -e $appimage ]] || die "not found: $appimage"
    appimage=$(readlink -f -- "$appimage")
    if [[ -d $appimage ]]; then
        # A .app bundle: run the binary inside it directly. `open` would go
        # through LaunchServices, which does not pass our environment on.
        exe_name=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' \
                       "$appimage/Contents/Info.plist" 2>/dev/null) || exe_name=''
        studio_bin=$appimage/Contents/MacOS/${exe_name:-BambuStudio}
    else
        studio_bin=$appimage
    fi
    [[ -f $studio_bin && -x $studio_bin ]] || die "not an executable: $studio_bin"
    studio_name=${studio_bin##*/}
else
    [[ -n $appimage ]] || { usage >&2; exit 2; }
    # [[ -f $appimage ]] || die "not a file: $appimage"
    [[ -x $appimage ]] || die "not executable: $appimage  (chmod +x it first)"
    appimage=$(readlink -f -- "$appimage")
    studio_bin=$appimage
    studio_name=${appimage##*/}
fi

# How to turn hex back into bytes -- tshark prints FT_BYTES fields as hex.
if command -v xxd >/dev/null; then          hex_decoder=xxd
elif command -v python3 >/dev/null; then    hex_decoder=python3
elif command -v perl >/dev/null; then       hex_decoder=perl
else die "need one of xxd, python3 or perl to decode the response body"; fi

hex_to_file() {  # $1 = hex string, $2 = output path
    case $hex_decoder in
        xxd)     printf '%s' "$1" | xxd -r -p > "$2" ;;
        python3) python3 -c 'import sys,binascii
open(sys.argv[2],"wb").write(binascii.unhexlify(sys.argv[1]))' "$1" "$2" ;;
        perl)    printf '%s' "$1" | perl -ne 'print pack("H*", $_)' > "$2" ;;
    esac
}

# Bambu Studio's own processes, by what they execute -- matching on the command
# line would also match this script, whose argv holds the AppImage path too.
studio_pids() {
    local pid exe
    if [[ $os == Darwin ]]; then
        # No /proc; the process name is the bundle's executable name.
        pgrep -x -- "$studio_name" 2>/dev/null | sort -un
        return
    fi
    {
        for pid in $(pgrep -f -- "$studio_name" 2>/dev/null); do
            [[ $pid == "$$" ]] && continue
            exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null) || continue
            # the AppImage runtime itself, or the binary inside its mount
            [[ $exe == "$appimage" || $exe == /tmp/.mount_* ]] && printf '%s\n' "$pid"
        done
        pgrep -x bambu-studio 2>/dev/null
    } | sort -un
}

# A running instance hands the launch off to the existing process, which was
# started without SSLKEYLOGFILE -- so no keys, and no fresh startup request.
if [[ -n $(studio_pids) ]]; then
    die "Bambu Studio is already running. Close it first -- a second launch reuses the existing process, which has no key log."
fi

if (( EUID == 0 )); then
    warn "running as root: Bambu Studio will run as root too, and will write to root's config."
elif [[ $os == Darwin ]]; then
    if [[ ! -r /dev/bpf0 ]]; then
        warn "/dev/bpf0 is not readable. If the capture fails, install ChmodBPF
         (it comes with the Wireshark installer, or run 'Install ChmodBPF.pkg'
         from Wireshark.app's Resources) and make sure you are in the
         access_bpf group, then log out and back in."
    fi
elif command -v getcap >/dev/null && ! getcap "$(command -v dumpcap)" 2>/dev/null | grep -q cap_net_raw; then
    warn "dumpcap has no cap_net_raw. If the capture fails, run:
           sudo dpkg-reconfigure wireshark-common   # then log out and back in
         or: sudo setcap cap_net_raw,cap_net_admin+eip \"$(command -v dumpcap)\""
fi

# --- output paths -----------------------------------------------------------
base=${basename_arg:-bambu-$(date +%Y%m%d-%H%M%S)}
cwd=$PWD
keylog="$cwd/$base-keys.log"
raw_pcap="$cwd/$base.pcapng"
dec_pcap="$cwd/$base-decrypted.pcapng"
trig_url="$cwd/$base-trigger-url.txt"
trig_json="$cwd/$base-trigger-response.json"

# Must exist and be writable before the first TLS handshake.
: > "$keylog" || die "cannot write $keylog"
export SSLKEYLOGFILE=$keylog
printf 'SSLKEYLOGFILE = %s\n' "$keylog"

# --- pick an interface ------------------------------------------------------
if [[ -z $interface ]]; then
    if [[ $os == Darwin ]]; then
        interface=$(route -n get default 2>/dev/null | awk '$1 == "interface:" {print $2; exit}')
    else
        interface=$(ip -o route show default 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')
    fi
fi
if [[ -z $interface ]]; then
    warn "could not auto-detect the interface; falling back to 1. Use --list-interfaces to choose."
    interface=1
fi
printf 'Interface     = %s\n' "$interface"

# --- cleanup ----------------------------------------------------------------
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/bambu-cap-XXXXXXXX") || die "mktemp failed"
dump_pid=''
mon_pid=''
studio_pid=''
my_pgid=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')

stop_pid() {  # $1 = pid, $2 = signal, graceful then KILL
    local pid=$1 sig=${2:-TERM} i
    [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null || return 0
    kill "-$sig" "$pid" 2>/dev/null || true
    for ((i = 0; i < 40; i++)); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.25
    done
    kill -KILL "$pid" 2>/dev/null || true
}

stop_studio() {
    [[ -n $studio_pid ]] || return 0
    printf 'Closing Bambu Studio...\n'
    # setsid gave it its own process group; kill the group so its children
    # (on Linux the AppImage's squashfs mount and the real binary) go with it.
    # Never signal our own group.
    local pgid
    pgid=$(ps -o pgid= -p "$studio_pid" 2>/dev/null | tr -d ' ')
    if [[ -n $pgid && $pgid != "$my_pgid" ]]; then
        kill -TERM "-$pgid" 2>/dev/null || true
        sleep 3
        kill -KILL "-$pgid" 2>/dev/null || true
    else
        stop_pid "$studio_pid" TERM
    fi
    # The startup check refused to run with any of these alive, so anything
    # still up is ours.
    local leftovers
    leftovers=$(studio_pids)
    [[ -n $leftovers ]] && kill -KILL $leftovers 2>/dev/null
    studio_pid=''
}

cleanup() {
    exec 3<&- 2>/dev/null || true
    [[ -n $mon_pid ]] && stop_pid "$mon_pid" TERM
    # SIGINT, not SIGKILL: dumpcap finalises the capture file on the way out.
    [[ -n $dump_pid ]] && stop_pid "$dump_pid" INT
    rm -rf -- "$tmpdir"
}
trap cleanup EXIT
trap 'exit 130' INT

# --- start the capture ------------------------------------------------------
dump_args=(-i "$interface" -w "$raw_pcap" -a "duration:$seconds")
[[ -n $capture_filter ]] && dump_args+=(-f "$capture_filter")

printf 'Starting capture...\n'
dumpcap "${dump_args[@]}" > "$tmpdir/dump.out" 2> "$tmpdir/dump.err" &
dump_pid=$!

# Do not launch Studio until the capture file actually exists, or the startup
# request can slip through before dumpcap is listening.
ready=0
for ((i = 0; i < 40; i++)); do
    kill -0 "$dump_pid" 2>/dev/null || break
    [[ -s $raw_pcap ]] && { ready=1; break; }
    sleep 0.25
done
if ! kill -0 "$dump_pid" 2>/dev/null; then
    wait "$dump_pid" 2>/dev/null
    printf '%s\n' "$(cat "$tmpdir/dump.err")" >&2
    dump_pid=''
    die "dumpcap exited immediately.
       If that was a permission error on the capture file: dumpcap writes it
       with reduced privileges, so under sudo it can fail in a directory owned
       by someone else.  Prefer giving dumpcap cap_net_raw and running this as
       yourself, without sudo."
fi
(( ready )) || warn "capture file did not appear; continuing anyway."
sleep 0.5

# --- live monitor -----------------------------------------------------------
# dumpcap has no content-based autostop, so a second, independent tshark reads
# the same interface and dissects as packets arrive.  It re-reads the key log
# whenever it meets a session it cannot decrypt yet, so secrets Bambu Studio
# appends after tshark started still take effect.  This process only decides
# *when to stop*; the raw dumpcap file plus the editcap pass below stay the
# authoritative copy.
if [[ -n $trigger_filter ]]; then
    mon_fifo="$tmpdir/mon.fifo"
    mkfifo "$mon_fifo"
    mon_args=(-i "$interface" -l -n -Q
              -o "tls.keylog_file:$keylog"
              -Y "$trigger_filter"
              -T fields -E separator='|'
              -e frame.number -e http.host -e http.request.uri
              -e http2.headers.authority -e http2.headers.path)
    [[ -n $capture_filter ]] && mon_args+=(-f "$capture_filter")
    tshark "${mon_args[@]}" > "$mon_fifo" 2> "$tmpdir/mon.err" &
    mon_pid=$!
    exec 3<> "$mon_fifo"        # read-write, so reads never block on EOF
    sleep 1.5                   # let it get on the wire
    if ! kill -0 "$mon_pid" 2>/dev/null; then
        warn "live monitor exited immediately: $(cat "$tmpdir/mon.err")"
        mon_pid=''
    else
        printf 'Monitor       = %s\n' "$trigger_filter"
    fi
fi

# --- launch Bambu Studio ----------------------------------------------------
# setsid: its own process group, so it can be killed as a unit later.
printf 'Launching %s\n' "$studio_bin"
new_session "$studio_bin" > "$tmpdir/studio.log" 2>&1 &
studio_pid=$!

# --- wait -------------------------------------------------------------------
# Rebuild the request URL from the monitor's fields:
#   frame.number|http.host|http.request.uri|http2.headers.authority|http2.headers.path
trigger_url() {
    local IFS='|' frame host uri auth path
    read -r frame host uri auth path <<<"$1"
    printf 'https://%s%s' "${host:-$auth}" "${uri:-$path}"
}

triggered=0
deadline=$(( $(date +%s) + seconds ))
while (( $(date +%s) < deadline )) && kill -0 "$dump_pid" 2>/dev/null; do
    if [[ -n $mon_pid ]] && IFS= read -r -t "$mon_timeout" line <&3; then
        if [[ -n ${line//[[:space:]|]/} ]]; then
            triggered=1
            url=$(trigger_url "$line")
            printf '\nTrigger matched: %s\n' "$url"
            printf '%s\n' "$url" > "$trig_url" || warn "cannot write $trig_url"
            if (( grace > 0 )); then
                printf 'Draining for %s s...\n' "$grace"
                sleep "$grace"
            fi
            break
        fi
        continue
    fi
    [[ -z $mon_pid ]] && sleep 0.5

    if [[ -t 0 ]] && read -rsn1 -t "$key_timeout" _key; then break; fi   # any key stops

    left=$(( deadline - $(date +%s) ))
    keys=$(grep -cE '^[A-Z_]+ ' "$keylog" 2>/dev/null); keys=${keys:-0}
    printf '\r  %s... %3ss left, %s key log lines   ' \
           "$( [[ -n $mon_pid ]] && printf watching || printf capturing )" \
           "$left" "$keys"
done
printf '\n'

[[ -n $mon_pid ]] && { stop_pid "$mon_pid" TERM; mon_pid=''; }
printf 'Stopping capture...\n'
stop_pid "$dump_pid" INT
wait "$dump_pid" 2>/dev/null
dump_pid=''

if (( triggered || close_studio )); then
    stop_studio
fi

# --- inject the secrets -----------------------------------------------------
key_lines=$(grep -cE '^[A-Z_]+ ' "$keylog" 2>/dev/null); key_lines=${key_lines:-0}
if (( key_lines == 0 )); then
    warn "the key log is empty -- Bambu Studio did not honour SSLKEYLOGFILE this run."
    warn "the raw capture is still at $raw_pcap but its TLS cannot be decrypted."
    exit 1
fi
printf 'Key log: %s secrets\n' "$key_lines"

editcap --inject-secrets "tls,$keylog" "$raw_pcap" "$dec_pcap" 2>&1 |
    sed 's/^/  editcap: /'
ec=${PIPESTATUS[0]}
(( ec == 0 )) || die "editcap failed with exit code $ec"
printf 'Wrote %s\n' "$dec_pcap"

# --- the exchange that matched the trigger ----------------------------------
# The live monitor is a separate capture, so its frame numbers mean nothing
# here; re-run the trigger filter over the decrypted file to locate the request
# and, through http.response_in, the response that answered it.
if [[ -n $trigger_filter ]]; then
    row=$(tshark -r "$dec_pcap" -Y "$trigger_filter" \
                 -T fields -E separator='|' -E occurrence=f \
                 -e http.response_in -e tcp.stream -e http2.streamid 2>/dev/null |
          grep -m1 -E '[0-9]' || true)

    if [[ -z $row ]]; then
        warn "the trigger matched live, but no packet in $dec_pcap matches the filter -- the request may not have decrypted in the offline pass."
    else
        IFS='|' read -r resp_in stream h2sid <<<"$row"

        # HTTP/1.1 requests carry http.response_in, which names the answering
        # frame outright.  HTTP/2 has no such field, so fall back to the body
        # -carrying packets of the same TCP (and HTTP/2) stream.
        hex=''
        for field in http.file_data http2.body.reassembled.data http2.data.data; do
            if [[ -n $resp_in ]]; then
                body_filter="frame.number == $resp_in"
            elif [[ -n $stream && -n $h2sid ]]; then
                body_filter="tcp.stream eq $stream and http2.streamid eq $h2sid and $field"
            elif [[ -n $stream ]]; then
                body_filter="tcp.stream eq $stream and $field"
            else
                break
            fi
            line=$(tshark -r "$dec_pcap" -Y "$body_filter" \
                          -T fields -e "$field" -E occurrence=f 2>/dev/null |
                   grep -m1 -E '[0-9a-fA-F]' || true)
            hex=$(printf '%s' "$line" | tr -cd '0-9a-fA-F')
            (( ${#hex} >= 2 && ${#hex} % 2 == 0 )) && break
            hex=''
        done

        if [[ -n $hex ]] && hex_to_file "$hex" "$trig_json"; then
            printf 'Wrote %s (%s bytes)\n' "$trig_json" "$(file_size "$trig_json")"
        else
            warn "no response body found for the triggered request."
        fi
    fi
fi

printf '\nFiles written to %s :\n' "$cwd"
for f in "$cwd/$base"*; do
    [[ -e $f ]] || continue
    printf '  %-40s %10s bytes\n' "${f##*/}" "$(file_size "$f")"
done
