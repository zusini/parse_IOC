#!/bin/bash
PATH_R=`pwd`
PATH_B="$PATH_R/maltrail/trails/static/"
PATH_A=$(echo "$PATH_B"|sed 's/\//\\\//g')
PATH_M="$PATH_R/maltrail/trails/static/malware"
PATH_S="$PATH_R/maltrail/trails/static/malicious" 
help_parse()
{
clear
echo "
"=========================== HELP ============================"
./parse_maltrail.sh -a  : gen full domain.csv ,  urls.csv,  ip_affect.csv
./parse_maltrail.sh -u  : update maltral from git  "
}
clone_maltrail()
{
if [ -x /usr/bin/git ]; then
    echo "Updating maltrail from git ....."
    /usr/bin/git clone https://github.com/stamparm/maltrail.git
    echo " Done update maltril."
else
    echo "Does not exist /usr/bin/git "
fi
}

parse_main()
{
if [[ -d "$PATH_M" ]] && [[ -d "$PATH_S" ]]
then    
	#parse domain.csv
	echo "Parse list cnc domain from maltrail ..... "
	grep -P "^.[^.]+\.[a-zA-Z].+\.[a-zA-Z]{1,6}$|^.[^.]+\.[a-zA-Z]{1,6}$|^.[^.]+\.[a-zA-Z]{1,6}$|^.[^.]+\.[a-zA-Z]{1,6}\.[a-zA-Z]{1,6}$" $PATH_M/*.txt > tmp.txt
	grep -P "^.[^.]+\.[a-zA-Z].+\.[a-zA-Z]{1,6}$|^.[^.]+\.[a-zA-Z]{1,6}$|^.[^.]+\.[a-zA-Z]{1,6}$|^.[^.]+\.[a-zA-Z]{1,6}\.[a-zA-Z]{1,6}$" $PATH_S/*.txt >> tmp.txt
	sed -i "s/$PATH_A//g" tmp.txt
        sed -i "s/malware\//malware_/g" tmp.txt
	sed -i "s/malicious\//malicious_/g" tmp.txt
	/usr/bin/vim -E -s tmp.txt <<-EOF
   		:g/#/d
		:g/\//d
		:g/\/d
		:g/\[/d
		:g/\]/d
		:g/\(/d
		:g/\)/d
   		:update
   		:quit
	EOF
	sed -i "s/:/,/g" tmp.txt
	/bin/cat tmp.txt|sort|uniq > $PATH_R/domain.csv
	echo "Done Parse list cnc domain from maltrail. "
	echo "Parse list url malware,cnc  from maltrail ..... "
	#parse urls.csv
	grep -P ".*" $PATH_M/*.txt > tmp.txt
	grep -P ".*" $PATH_S/*.txt >> tmp.txt
	sed -i "s/$PATH_A//g" tmp.txt
        sed -i "s/malware\//malware_/g" tmp.txt
        sed -i "s/malicious\//malicious_/g" tmp.txt
	/usr/bin/vim -E -s tmp.txt <<-EOF
                :g/#/d
		:g!/\//d
		:g/Reference/d
		:g/twitter.com/d
                :g/\[/d
                :g/\]/d
                :g/\(/d
                :g/\)/d
		:g/ftp:\/\//d	
		:%s/http:\/\///g
		:%s/https:\/\///g
		:%s/txt:/txt,*/g
		:%s/\/$/\/*/g
		:%s/=$/=*/g
		:g/\(\d\{1,3\}[.]\)\{3\}\(\d\{1,3\}\)$/d
                :update
                :quit
	EOF
	/bin/cat tmp.txt|sort|uniq >  $PATH_R/urls.csv
	echo "Done list url malware,cnc  from maltrail. "
	echo "Parse list IP malware,cnc  from maltrail ..... "
	 #parse ip_affect.csv
	grep -P "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" $PATH_M/*.txt  > tmp.txt
	grep -P "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" $PATH_S/*.txt  >>  tmp.txt
	sed -i "s/$PATH_A//g" tmp.txt
        sed -i "s/malware\//malware_/g" tmp.txt
        sed -i "s/malicious\//malicious_/g" tmp.txt
	/usr/bin/vim -E -s tmp.txt <<-EOF
                :g/#/d
		:g/\//d
                :g/Reference/d
                :g/twitter.com/d
                :g/\[/d
                :g/\]/d
                :g/\(/d
                :g/\)/d
                :g/ftp:\/\//d
                :%s/http:\/\///g
                :%s/https:\/\///g
                :%s/txt:/txt,/g
		:%s/:/,/g
                :update
                :quit
	EOF
	/bin/cat tmp.txt|sort|uniq >  $PATH_R/ip_affect.csv
	/bin/rm -rf  $PATH_R/tmp.txt
	echo "Done parse list IP malware,cnc  from maltrail ..... "

else
	echo "Not  path  $PATH_B."
fi 
}
#============================  SCRIPT ==========================================
#MAIN SCRIPT

if [ -z $1 ]
then
        help_parse
elif [ $1 = '-h' ] || [ $1 = '-help' ]
then
        help_parse
elif [ $1 = '-a' ]
then
        clear
        echo "+++++++++++++++++++Parse full ++++++++++++++++++++++"
        parse_main 
        
elif [ $1 = '-u' ]
then
        clear
        echo "+++++++++++++++++++Update maltrail IOC ++++++++++++++++++++++"
	clone_maltrail
else
        helpssh
fi
