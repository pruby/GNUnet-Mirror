#! /bin/bash

# gnunet-stats-pretty -- filter and beautify gnunet-stats' output
# Copyright (C) David Kuehling 2008

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


# fixed point division with string result printed to stdout
#
# $1: numerator
# $2: denominator
# $3: number of fractional digits 
fixdiv() {

    numerator=$1
    denom=$2
    fracdigits=$3

    if (( denom == 0 )); then
	(( intpart = 0 ))
	(( fracpart = 0 ))
    else
	(( intpart = numerator / denom ))
	(( fracfactor = 10 ** fracdigits ))
	(( fracpart = (numerator * fracfactor / denom) % fracfactor ))
    fi
    printf "%i.%0${fracdigits}i" $intpart $fracpart    
}

# convert time span in seconds to human readable representation
seconds2str() {
    t="$1"
    (( days = t/86400 )) 
    (( hours = (t/3600) % 24 )) 
    (( minutes = (t/60) % 60 )) 
    (( seconds = t % 60 )) 

    (( days > 0 )) && printf "%i Tage, " $days
    (( days > 0 || hours > 0 )) && printf "%i Stunden, " $hours

    printf "%i minuten" $minutes

    (( hours == 0 )) && printf ", %i Sekunden" $seconds
}

print_rate_by_type() {

    total="$1"
    shift 1
    uptime="$1"
    type=0
    while shift 1; do
	bytes=$1
	if (( bytes > total / 1000 )); then
	    printf "  %2i %-32s %4s KiB/s (%4s %% of total)\n" \
		$type "(${proto2name[$type]})" \
		$(fixdiv $((bytes)) $((1024*uptime)) 1) \
		$(fixdiv $((bytes*100)) $total 1)
	fi
	(( type += 1 ))
    done
}

#
# initialize arrays
#
for i in $(seq 0 66); do
    recv_by_type[$i]=0
    sent_by_type[$i]=0
done

proto2name[0]="RETURN_VALUE"
proto2name[1]="SHUTDOWN_REQUEST"
proto2name[2]="GET_OPTION_REQUEST"
proto2name[3]="GET_OPTION_REPLY"
proto2name[4]="RETURN_ERROR"
proto2name[8]="GAP_QUERY_START"
proto2name[9]="GAP_RESULT"
proto2name[10]="GAP_INSERT"
proto2name[11]="GAP_INDEX"
proto2name[12]="GAP_DELETE"
proto2name[13]="GAP_UNINDEX"
proto2name[14]="GAP_TESTINDEX"

proto2name[18]="DHT_DISCOVERY"
proto2name[19]="DHT_ASK_HELLO"
proto2name[20]="DHT_GET"
proto2name[21]="DHT_PUT"
proto2name[22]="DHT_RESULT"

proto2name[25]="IDENTITY_REQUEST_INFO"
proto2name[26]="IDENTITY_INFO"
proto2name[27]="IDENTITY_REQUEST_HELLO "
proto2name[28]="IDENTITY_HELLO"
proto2name[29]="IDENTITY_REQUEST_SIGNATURE"
proto2name[30]="IDENTITY_SIGNATURE"
proto2name[31]="IDENTITY_CONNECT"

proto2name[36]="TRACEKIT_PROBE"
proto2name[37]="TRACEKIT_REPLY"

proto2name[40]="TBENCH_REQUEST"
proto2name[41]="TBENCH_REPLY"

#
# parse output of gnunet-stats
#
while read -d: key; do
    read val

    case "$key" in
	"Laufzeit (Sekunden)")
	    uptime=$val
	    ;;
 	"# Bytes empfangen über UDP")
	    recv_udp=$val;
	    ;;
 	"# Bytes gesendet über UDP")
	    sent_udp=$val
	    ;;
 	"# Bytes empfangen über TCP")
	    recv_tcp=$val
	    ;;
 	"# Bytes gesendet über TCP")
	    sent_tcp=$val
	    ;;
 	"# bytes transmitted")
	    sent=$val
	    ;;
 	"# Bytes ausgehender Nachrichten verworfen")
	    bytes_omsg_dropped=$val
	    ;;
 	"# bytes received")
	    recv=$val
	    ;;
	"# Bytes des Typs empfangen "*)
	    read _hash _bytes _received _of _type type <<<"$key"
	    recv_by_type[$type]=$val
	    ;;
	"# Bytes des Typs übertragen "*)
	    read _hash _bytes _transmitted _of _type type <<<"$key"
	    sent_by_type[$type]=$val
	    ;;
	"# gap requests total received")
	    gap_req_recv=$val
	    ;;
	"# gap requests dropped due to load")
	    gap_req_drop=$val
	    ;;
	"# gap requests total sent")
	    gap_req_sent=$val
	    ;;
	"# requests filtered by bloom filter")
	    nbloom=$val
	    ;;
	"# bloom filter false positives")
	    bloom_err=$val
	    ;;
	"# bytes allowed in datastore")
	    ds_size=$val
	    ;;
        "# bytes in dstore")
	    ds_used=$val
	    ;;
        "# verbundener Knoten")
	    nconn=$val
	    ;;
        "# dht connections")
	    ndhtconn=$val
	    ;;
	"# average connection lifetime (in ms)")
	    av_conn_t_ms=$val
	    ;;
        "# conn. shutdown")
	    # key contains ':', so part of the key has been stored in 'val'
	    # we need a second parsing attempt to process the second ':'
	    { read -d: reason; read val; } <<<"$val"
	    case "$reason" in
		"timed out during connect")
		    nconn_timeout=$val
		    ;;
	    esac
    esac
done < <( gnunet-stats )

#
# output statistics
#

printf "Laufzeit: %s\n" "$(seconds2str $uptime)"

printf "Durchschnittliche Uebertragungs-Datenrate: %s KiB/s (%s %% TCP, %s %% UDP)\n"  \
    $(fixdiv $sent $((uptime*1024)) 2) \
    $(fixdiv $((sent_tcp*100)) $sent 2) \
    $(fixdiv $((sent_udp*100)) $sent 2) 

printf "Protokolle mit durchschnittlicher Uebertragungs-Datenrate > 0.1 %% insgesamt\n"
print_rate_by_type $sent $uptime "${sent_by_type[@]}"

printf "Datenrate von fallengelassenen ausgehenden Nachrichten: %s KiB/s\n"  \
    $(fixdiv $bytes_omsg_dropped $((uptime*1024)) 2) \

printf "Durchschnittle Empfangs-Datenrate: %s KiB/s (%s %% TCP, %s %% UDP)\n"  \
    $(fixdiv $recv $((uptime*1024)) 2) \
    $(fixdiv $((recv_tcp*100)) $recv 2) \
    $(fixdiv $((recv_udp*100)) $recv 2) 

printf "Protokolle mit durchschnittlicher Empfangs-Datenrate > 0.1 %% insgesamt\n"
print_rate_by_type $recv $uptime "${recv_by_type[@]}"

printf "Datastore-Benutzung: %s MiB / %s MiB (%s %%)\n"  \
    $(fixdiv $ds_used $(( 1024**2 )) 0) \
    $(fixdiv $ds_size $(( 1024**2 )) 0) \
    $(fixdiv $((ds_used*100)) $ds_size 1)

if ((nbloom == 0)); then
    nbloom=1
    bloom_err=0
fi

printf "GAP-Anfragen empfangen: %s Anfragen/Min (%s %% dropped)\n"  \
    $(fixdiv $((gap_req_recv*60)) $uptime 1) \
    $(fixdiv $((gap_req_drop*100)) $gap_req_recv 1) \

printf "GAP-Anfragen gesendet: %s Anfragen/Min\n"  \
    $(fixdiv $((gap_req_sent*60)) uptime 1)

printf "Bloom-Filter Fehlrate: %s %%\n"  \
    $(fixdiv $((bloom_err*100)) $nbloom 1)

printf "Anzahl Verbindungen: %i\n"  $nconn
printf "Durchschnittle Lebenszeit von Verbindungen: %s\n" \
    "$(seconds2str $((av_conn_t_ms / 1000)) )"
printf "Rate fehlgeschlagener Verbindungs-Versuche durch Timeout: %s Versuche/Stunde\n"\
    $(fixdiv $((nconn_timeout*3600)) $uptime 1)
