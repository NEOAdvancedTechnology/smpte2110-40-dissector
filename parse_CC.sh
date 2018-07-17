#!/bin/sh

WS_PLUGIN=ST2110-40.lua
PCAP_FILE=
OUT_FILE=
DEBUG=

usage()
{
	echo "$0 --in=<PCAP> [--out=<DATA_FILE> | -v]"
	echo "\t -h --help"
	echo "\t --in=<pcap_file>"
	echo "\t --out=<CC_file> : output in a file"
	echo "\t -v --verbose : output in stdout"
	echo ""
}

if [ "$#" -lt 2 ]; then
	usage
	exit 1
fi

while [ "$1" != "" ]; do
	PARAM=`echo $1 | awk -F= '{print $1}'`
	VALUE=`echo $1 | awk -F= '{print $2}'`
	case $PARAM in
		-h | --help)
			usage
			exit
			;;
		--in)
			PCAP_FILE="$VALUE"
			;;
		--out)
			OUT_FILE="$VALUE"
			;;
		-v | --verbose)
			DEBUG=1
			;;
		*)
			echo "ERROR: unknown parameter \"$PARAM\""
			usage
			exit 1
			;;
	esac
	shift
done

# checking if --in has been filled
if [ ! ${PCAP_FILE} ]; then
	usage
	exit 1
fi

# checking if an output is filled
if [ ! "${OUT_FILE}" -a ! "${DEBUG}" ]; then
	usage
	exit 1
fi

# checking if the capture exists
if [ ! -f "${PCAP_FILE}" ]; then
	echo "The pcap file does not exist"
	exit 1
fi

# copy the plugin in Wireshark's plugin directory
cp $WS_PLUGIN ${HOME}/.config/wireshark/plugins/

# extraction the CC Data
# as tshark extract the field st_2110_40.Data.CCData for each packet
# even if they are null, these lines are cut off with grep
if [ ${DEBUG} ]; then
	tshark -r $PCAP_FILE -o data.show_as_text:TRUE -T fields -e st_2110_40.Data.CCData | grep -Ei "^[A-F0-9]" | tr -d "\n" | xxd -r -p
fi

if [ ${OUT_FILE} ]; then

	tshark -r $PCAP_FILE -o data.show_as_text:TRUE -T fields -e st_2110_40.Data.CCData | grep -Ei "^[A-F0-9]" | tr -d "\n" | xxd -r -p > ${OUT_FILE}
fi
