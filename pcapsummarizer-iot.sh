#!/bin/bash
# A script to summarize some information about a pcap file.
# The First parameter is the _folder_ with ONE pcap file.
# The second parameter can be -a if you want to redo the files even if they exist. By default if they exist we don't recreate them
# Author: Sebastian Garcia, eldraco@gmail.com

if [[ $2 == '-a' ]]; then
    # If the parameter is not empty and it is a folder
    AGAIN=1
fi

if [[ -d $1 ]]; then
    # If the name is not empty and it is a folder
    echo "Entering $1"
    cd $1

    # Do we have a pcap file?
    pcapfiles=$(find . -name "*.pcap")
    
    # Get the name of the pcap file if it is still "capture*"
    if [[ $pcapfiles != "" ]]; then
        echo "Summarizing pcap files in $1"
        for pcapfile in *.pcap; do

            # Fixing the pcap in case is broken 
            echo "Fixing the pcap in case is broken"
            pcapfix $pcapfile
            mv fixed_$pcapfile $pcapfile

            NAME=$(echo "$pcapfile"|awk -F".pcap" '{print $1}')
            echo -e "\tWorking with pcap file $pcapfile"

            # 1st, get rid of multicast and broadcast
            # If we run this in a live capture, do not move the pcap!

            # Dnstop
            if [[ $AGAIN || ! -f $NAME.dnstop ]]; then
                echo -e "\t\tCreating DNSTOP file $NAME.dnstop"
                dnstop $pcapfile -l 4 > $NAME.dnstop
            fi

            # passivedns
            if [[ $AGAIN || ! -f $NAME.passivedns ]]; then
                echo -e "\t\tCreating passivedns file $NAME.passivedns"
                passivedns -r $pcapfile -l - > $NAME.passivedns
            fi

            # Is bro already there?
            if [[ $AGAIN || ! -d bro ]]; then
                echo -e "\t\tCreating Bro files"
                mkdir bro
                /usr/local/bro/bin/bro -C -r $pcapfile local
                mv -f *.log bro
            fi

            # Is suricata already there?
            SURICATA_VERSION=$(suricata -V)
            echo -e "\t\tUsing Suricata Version $SURICATA_VERSION"
            if [[ $AGAIN || ! -d suricata ]]; then
                echo -e "\t\tCreating Suricata files"
                mkdir suricata
                suricata -r $pcapfile -l .
                mv -f *.log suricata
                mv -f *.json suricata
                EVEFILE="suricata/eve.json"

                # Autoupdate to Proofpoint the suricata eve.log file
                timeout 10s ssh stratosphere@drop.emergingthreatspro.com 'mkdir incoming/$NAME'
                timeout 10s scp $EVEFILE stratosphere@drop.emergingthreatspro.com:incoming/$NAME/

                # Check if the suricata update date is on the readme or not
                # Do we have the line already in the README?
                ISLINE=$(grep "Suricata run" README.md)
                SURICATAUPDATEDATE=$(stat /var/lib/suricata/rules/suricata.rules|grep Modify|awk '{print $2}')
                if [[ ! $ISLINE ]]; then
                    # Is not there. Add date
                    echo -e "\n# Suricata run with rules updated on $SURICATAUPDATEDATE" |tee -a README.md
                else
                    # Is there. Replace date
                    sed -i "s/Suricata.*/Suricata run with rules updated on $SURICATAUPDATEDATE/g" README.md
                fi
            fi


            # Capinfos
            if [[ $AGAIN || ! -f $NAME.capinfos ]]; then
                echo "Creating the capinfos file"
                /usr/bin/capinfos $pcapfile > $NAME.capinfos
            fi

            # Sebas telnet analyzer
            if [[ $AGAIN || ! -f $NAME.telnet_info ]]; then
                ISTELNET=$(cat bro/conn.log |awk -F'\t' '{if ($6=='23') print $0}')
                if [[ $ISTELNET ]]; then
                    /opt/Malware-Project/tools/telnet-analyzer/telnet-analyzer.py -r $pcapfile > $NAME.telnet_info
                fi
            fi


            # Convert to weblogs
            ######### Commented by MJE nov the 8th.. The script got stuck here and running multiple script lost connection to Jin 
            #if [[ $AGAIN || ! -f $NAME.weblogng ]]; then
            #    echo "Creating the weblogng file"
            #    convert-pcap-to-weblogs.sh $pcapfile
            #fi

            # tcpdstat
            #if [[ $AGAIN || ! -f $NAME.tcpdstat ]]; then
            #    echo "Creating the tcpdstat file"
            #    tcpdstat $pcapfile > $NAME.tcpdstat
            #fi

            # Bidirectional argus Flow file
           # if [[ $AGAIN || ! -f $NAME.biargus ]]; then
           #     echo "Creating the biargus file"
           #     argus -r $pcapfile -F /opt/Malware-Project/Dataset/Botnet-Capture/defaultConfigFiles/argus_bi.conf -w $NAME.biargus
           # fi
            # Bidirectional flow text file.
           # if [[ $AGAIN || ! -f $NAME.binetflow ]]; then
           #     echo "Creating the binetflow file"
           #     ra -Z b -n -r $NAME.biargus -F /opt/Malware-Project/Dataset/Botnet-Capture/defaultConfigFiles/ra.conf.analysis > $NAME.binetflow
           # fi

            # Unidirectional NetFlow argus binary file, NetflowV5 kind of
            #if [[ $AGAIN || ! -f $NAME.uniargus ]]; then
                #echo "Creating the uniargus file"
                #argus -r $pcapfile -F /opt/Malware-Project/Dataset/Botnet-Capture/defaultConfigFiles/argus.uninetflow.conf -w $NAME.uniargus
            #fi
            ## Unidirectional Netflow text file. NEtflowv5 kind of
            #if [[ $AGAIN || ! -f $NAME.uninetflow ]]; then
                #echo "Creating the uninetflow file"
                #ra -n -r $NAME.uniargus -F /opt/Malware-Project/Dataset/Botnet-Capture/defaultConfigFiles/ra.uninetflow.conf > $NAME.uninetflow
            #fi
            # Mitm weblogs for the https dataset
            #if [[ -f mitm.out ]]; then
                #if [[ $AGAIN || ! -f $NAME.mitm.weblog ]]; then
                    #echo "Creating the .mitm.weblog file"
                    #TEMP=$(pwd|awk -F\/ '{print $NF}'|awk -F- '{print $(NF-1)"-"$NF}'|sed 's/-/./')
                    #LABEL="CTU.$TEMP.Malicious"
                    #/usr/local/bin/mitmdump -n --no-http2 -q -r mitm.out -s "/opt/Malware-Project/tools/Project-Nomad/nomad-extractor.py $NAME.mitm.weblog $LABEL"
                #fi
            #else
                #echo "No mitm dump file to process."
            #fi
            # Create the automated fastflux and DGA analysis
            #if [[ $AGAIN || ! -f fast-flux-dga-first-analysis.txt ]]; then
            #    echo -e "\t\tGenerating the automated fast flux and DGA analysis"
            #    check-fastflux-in-all-domains.sh >> fast-flux-dga-first-analysis.txt
            #fi

            # Automatically create the encrypted zip file
            ## For exe
            exe=$(ls *.exe)
            exename=$(echo "$exe"|awk -F".exe" '{print $1}')
            zip=$exename.zip
            echo $exe
            echo $zip
            if [[ $AGAIN || ! -f $zip ]]; then
                echo -e "\t\tEncrypting the exe file into a zip wih password 'infected'"
                zip -e $zip -P infected $exe
                if [[ -f $zip ]]; then
                    rm $exe
                fi
            fi
            ## For bash
            bash=$(ls *.sh)
            bashname=$(echo "$bash"|awk -F".sh" '{print $1}')
            zip=$bashname.zip
            echo $bash
            echo $zip
            if [[ $AGAIN || ! -f $zip ]]; then
                echo -e "\t\tEncrypting the bash file into a zip wih password 'infected'"
                zip -e $zip -P infected $bash
                if [[ -f $zip ]]; then
                    rm $bash
                fi
            fi

            ## For ELF
            elfname=$(file *|grep ELF|cut -f 1 -d ":")
            zip=$elfname.zip
            echo $elf
            echo $zip
            if [[ $AGAIN || ! -f $zip ]]; then
                echo -e "\t\tEncrypting the ELF file into a zip wih password 'infected'"
                zip -e $zip -P infected $elf
                if [[ -f $ZIp ]]; then
                    rm $elf
                fi
            fi


        done

        # Create the .html
        echo -e "\t\tCreating the html file"
        pandoc README.md -o README.html

        # Do we have the exe file?
        #exe=$(ls *.exe)
        #if [[ ! $exe ]];then
            #echo -e "\t\tThere is no exe file"
            #md5=$(grep MD5 README.md| awk -F: '{print $2}')
            #if [[ $md5 != "" ]]; then
                #echo -e "\t\tCopying the exe file"
                #currentdir=$(pwd)
                #cd /opt/Malware-Project/malware-to-test/shared-folder/
                #cp $md5.exe $currentdir
                #cd $currentdir
            #else
                #echo -e "\t\tNo MD5 in README.md"
            #fi
        #fi

        # Permisions of the pcap files
        echo -e "\t\tChanging the permsions of the pcap file to 644"
        chmod 644 *.pcap

        # Delete the nohup.out file
        if [[ -f nohup.out ]]; then
            rm nohup.out
        fi  
    else
        echo -e "\t\tNo pcap files"
    fi
fi
