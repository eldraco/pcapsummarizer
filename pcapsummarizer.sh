#!/bin/bash
if [[ -d $1 ]]; then
    # If the name is not empty and it is a folder
    echo "Entering $1"
    cd $1

    # Do we have a pcap file?
    pcapfiles=$(find . -name "*.pcap")
    if [[ $pcapfiles != "" ]]; then
        echo "Summarizing pcap files in $1"
        for pcapfile in *.pcap; do
            NAME=$(echo "$pcapfile"|awk -F".pcap" '{print $1}')
            echo -e "\tWorking with pcap file $pcapfile"

            # Dnstop
            if [[ ! -f $NAME.dnstop ]]; then
                echo -e "\t\tCreating DNSTOP file $NAME.dnstop"
                /usr/bin/dnstop $pcapfile -l 4 > $NAME.dnstop
            fi

            #passivedns
            if [[ ! -f $NAME.passivedns ]]; then
                echo -e "\t\tCreating passivedns file $NAME.passivedns"
                /usr/local/bin/passivedns -r $pcapfile -l - > $NAME.passivedns
            fi

            # Is bro already there?
            if [[ ! -d bro ]]; then
                echo -e "\t\tCreating Bro files"
                mkdir bro
                cd bro
                /opt/bro/bin/bro -r ../$pcapfile
                cd ..
            fi
        done

        # Create the .html
        echo -e "\t\tCreating the html file"
        /usr/bin/pandoc README.md -o README.html

        # Do we have the exe file?
        exe=$(ls *.exe)
        if [[ ! $exe ]];then
            echo -e "\t\tThere is no exe file"
            md5=$(grep MD5 README.md| awk -F: '{print $2}')
            if [[ $md5 != "" ]]; then
                echo -e "\t\tCopying the exe file"
                currentdir=$(pwd)
                cd /opt/Malware-Project/malware-to-test/shared-folder/
                cp $md5.exe $currentdir
                cd $currentdir
            else
                echo -e "\t\tNo MD5 in README.md"
            fi
        fi

        # Permisions of the pcap files
        echo -e "\t\tChanging the permsions of the pcap file to 644"
        chmod 644 *.pcap
    else
        echo -e "\t\tNo pcap files"
    fi
fi
