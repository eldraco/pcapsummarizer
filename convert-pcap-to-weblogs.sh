#!/bin/bash
PCAPFILE=`echo $1| sed 's/^.\///g'`

FILE=`echo $PCAPFILE|awk -F. '{print $1}'`

echo "timestamp	s-port	sc-http-status	sc-bytes	sc-header-bytes	c-port	cs-bytes	cs-header-bytes	cs-method	cs-url	s-ip	c-ip	connection.time	request.time	response.time	close.time	idle.time0	idle.time1	cs-mime-type	cs(Referer)	cs(User-Agent)" > $FILE.weblogng

# Times are in seconds
#justniffer -f $PCAPFILE -c /opt/Malware-Project/Dataset/Botnet-Capture/defaultConfigFiles/justsniffer.conf -l "%request.timestamp2(%s) %dest.port %response.code %response.size %response.header.content-length(0) %source.port %request.size %request.header.content-length(0) %request.method http://%request.header.host%request.url %dest.ip %source.ip %connection.time %request.time %response.time %close.time %idle.time.0 %idle.time.1 \"%response.header.content-type\" \"%request.header.referer\" \"%request.header.user-agent\""| awk '{printf "%.6f|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%.6f|%.6f|%.6f|%.6f|%.6f|%.6f|%s|%s|%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50, $51, $52, $53, $54}' |  sed 's/^[ \t]*//;s/[ \t]*$//' >> $FILE.weblogng

# Try
#justniffer -f $PCAPFILE -c /opt/Malware-Project/Dataset/Botnet-Capture/defaultConfigFiles/justsniffer.conf -l "%request.timestamp2(%s)|%dest.port|%response.code|%response.size|%response.header.content-length(0)|%source.port|%request.size|%request.header.content-length(0)|%request.method|http://%request.header.host%request.url|%dest.ip|%source.ip|%connection.time|%request.time|%response.time|%close.time|%idle.time.0|%idle.time.1|\"%response.header.content-type\"|\"%request.header.referer\"|\"%request.header.user-agent\"" >> $FILE.weblogng


justniffer -f $PCAPFILE -c /opt/Malware-Project/Dataset/Botnet-Capture/defaultConfigFiles/justsniffer.conf -l "%request.timestamp2(%s)	%dest.port	%response.code	%response.size	%response.header.content-length(0)	%source.port	%request.size	%request.header.content-length(0)	%request.method	http://%request.header.host%request.url	%dest.ip	%source.ip	%connection.time	%request.time	%response.time	%close.time	%idle.time.0	%idle.time.1	\"%response.header.content-type\"	\"%request.header.referer\"	\"%request.header.user-agent\"" >> $FILE.weblogng
