#!/bin/bash
PCAPFILE=$1
FILE=`echo $PCAPFILE|awk -F. '{print $1}'`

# old
#justniffer -f $1 -c /opt/Malware-Project/Dataset/Botnet-Capture/defaultConfigFiles/justsniffer.conf | awk '{if ($15 ~ "charset=") {print $1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "$10" "($11*1000)" "$12" "$13" "substr($14,1,match($14,/\;/)-1)" "$16" "$17" "$18" "$19" "$20" "$21" "$22" "$23" "$24" "$25" "$26" "$27" "$28" "$29" "$30" "$31" "$32" "$33" "$34" "$35" "$36" "$37" "$38" "$39" "$40" "$41} else if ($14 ~ /;/) { print $1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "$10" "($11*1000)" "$12" "$13" "substr($14,1,match($14,/\;/)-1)" "$15" "$16" "$17" "$18" "$19" "$20" "$21" "$22" "$23" "$24" "$25" "$26" "$27" "$28" "$29" "$30" "$31" "$32" "$33" "$34" "$35" "$36" "$37" "$38" "$39" "$40" "$41} else {print $1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "$10" "($11*1000)" "$12" "$13" "$14" "$15" "$16" "$17" "$18" "$19" "$20" "$21" "$22" "$23" "$24" "$25" "$26" "$27" "$28" "$29" "$30" "$31" "$32" "$33" "$34" "$35" "$36" "$37" "$38" "$39" "$40" "$41}}' | awk '{printf "%.3f|%s|%s|%s|%s|%s|%s|%s|%s|%s|%.0f|%s|%s|%s|%s|%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41}' | sed 's/^[ \t]*//;s/[ \t]*$//' >> $FILE.weblogng

echo "timestamp|s-port|sc-http-status|sc-bytes|sc-header-bytes|c-port|cs-bytes|cs-header-bytes|cs-method|cs-url|x-elapsed-time|s-ip|c-ip|cs-mime-type|cs(Referer)|cs(User-Agent)" > $FILE.weblogng
#justniffer -f $PCAPFILE -c /opt/Malware-Project/Dataset/Botnet-Capture/defaultConfigFiles/justsniffer.conf  | awk '{printf "%.3f|%s|%s|%s|%s|%s|%s|%s|%s|%s|%.0f|%s|%s|%s %s|%s|%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49}' |  sed 's/^[ \t]*//;s/[ \t]*$//'  >> $FILE.weblogng

justniffer -f $PCAPFILE -c /etc/justsniffer.conf -l "%request.timestamp2(%s) %dest.port %response.code %response.size %response.header.content-length(0) %source.port %request.size %request.header.content-length(0) %request.method http://%request.header.host%request.url %connection.time %dest.ip %source.ip \"%response.header.content-type\" \"%request.header.referer\" \"%request.header.user-agent\" "| awk '{printf "%.3f|%s|%s|%s|%s|%s|%s|%s|%s|%s|%.0f|%s|%s|%s %s|%s|%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11*1000, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49}' |  sed 's/^[ \t]*//;s/[ \t]*$//' >> $FILE.weblogng