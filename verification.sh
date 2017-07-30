#!/bin/bash

#!/bin/bash
#Remove all output
exec 2>/dev/null

#To stop “Control-C”
trap '' 2

#To stop “Control-Z”
trap '' SIGTSTP

#Check if the verification results file exists and if not create one
cd ~/Desktop
vFile="./verification.txt"
if [ -e "$vFile" ]
then
    	rm -f verification.txt
        touch verification.txt
else
    	touch verification.txt
fi

echo "--FILE SYSTEM CONFIGURATIONS-- " >> ./verification.txt
#Check for the correct configurations for /tmp
checktmp=`grep "[[:space:]]/tmp[[:space:]]" /etc/fstab`

if [ -z "$checktmp" ]
then
	echo "[FAILED]A separate /tmp partition has not been created." >> ./verification.txt
	echo "" >> ./verification.txt
else
	checknodev=`grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nodev`
	checknodev1=`mount | grep "[[:space:]]/tmp[[:space:]]" | grep nodev`
	if [ -z "$checknodev" -a -z "$checknodev1" ]
	then
		echo "[FAILED] Please ensure that /tmp is mounted with nodev option." >> ./verification.txt
		echo "" >> ./verification.txt
	elif [ -z "$checknodev" -a -n "$checknodev1" ]
	then
		echo "[FAILED] Please ensure that /tmp is mounted persistently with nodev option." >> ./verification.txt
		echo "" >> ./verification.txt
	elif [ -n "$checknodev" -a -z "$checknodev1" ]
	then
		echo "[FAILED] Please ensure /tmp is currently mounted with nodev option." >> ./verification.txt
		echo "" >> ./verification.txt
	else
		checknosuid=`grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nosuid`
		checknosuid1=`mount | grep "[[:space:]]/tmp[[:space:]]" | grep nosuid`
		if [ -z "$checknosuid" -a -z "$checknosuid1" ]
		then
			echo "[FAILED] Please ensure that /tmp is mounted with nosuid option." >> ./verification.txt
			echo "" >> ./verification.txt
		elif [ -z "$checknosuid" -a -n "$checknosuid1" ]
		then
			echo "[FAILED] Please ensure that /tmp is mounted persistently with nosuid option." >> ./verification.txt
			echo "" >> ./verification.txt
		elif [ -n "$checknosuid" -a -z "$checknosuid1" ]
		then
			echo "[FAILED] Please ensure that /tmp is currently mounted with nosuid option." >> ./verification.txt
			echo "" >> ./verification.txt
		else	
			checknoexec=`grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep noexec`
			checknoexec1=`mount | grep "[[:space:]]/tmp[[:space:]]" | grep noexec`
			if [ -z "$checknoexec" -a -z "$checknoexec1" ]
			then
				echo "[FAILED] Please ensure that /tmp is mounted with noexec option." >> ./verification.txt
				echo "" >> ./verification.txt
			elif [ -z "$checknoexec" -a -n "$checknoexec1" ]
			then
				echo "[FAILED] Please ensure that /tmp is mounted persistently with noexec option." >> ./verification.txt
				echo "" >> ./verification.txt
			elif [ -n "$checknoexec" -a -z "$checknoexec1" ]
			then
				echo "[FAILED] Please ensure that /tmp is currently mounted with noexec option." >> ./verification.txt
				echo "" >> ./verification.txt
			else
				echo "[PASS] /tmp is a separate partition with nodev, nosuid, noexec option." >> ./verification.txt
				echo "" >> ./verification.txt
			fi
		fi
	fi
fi

#Check for the correct configurations for /var
checkvar=` grep "[[:space:]]/var[[:space:]]" /etc/fstab`
if [ -z "$checkvar" ]
then
	echo "[FAILED] Please ensure that a separate /var partition has been created." >> ./verification.txt
	echo "" >> ./verification.txt
else 
	echo "[PASS] A separate /var partition has been created." >> ./verification.txt
	echo "" >> ./verification.txt
fi	

#Check if /var/tmp directory is binded and mounted to /tmp
checkbind=`grep -e "^/tmp[[:space:]]" /etc/fstab | grep /var/tmp` 
checkbind1=`mount | grep /var/tmp`
if [ -z "$checkbind" -a -z "$checkbind1" ]
then
	echo "[FAILED] Please ensure that /var/tmp mount is bounded to /tmp." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ -z "$checkbind" -a -n "$checkbind1" ]
then
	echo "[FAILED] Please ensure that /var/tmp mount has been binded to /tmp persistently." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ -n "$checkbind" -a -z "$checkbind1" ]
then
	echo "[FAILED] Please ensure that /var/tmp mount is currently bounded to /tmp." >> ./verification.txt
	echo "" >> ./verification.txt
else 
	echo "[PASS] var/tmp has been binded and mounted to /tmp." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check for separate partition for /var/log
checkvarlog=`grep "[[:space:]]/var/log[[:space:]]" /etc/fstab`
if [ -z "$checkvarlog" ]
then
	echo "[FAILED] Please ensure that a separate /var/log partition has been created." >> ./verification.txt
	echo "" >> ./verification.txt
else 
	echo "[PASS] A separate /var/log partition has been created." >> ./verification.txt
	echo "" >> ./verification.txt
fi	

#Check for separate partition for /var/log/audit
checkvarlogaudit=`grep "[[:space:]]/var/log/audit[[:space:]]" /etc/fstab`
if [ -z "$checkvarlogaudit" ]
then
	echo "[FAILED] Please ensure that a separate /var/log/audit partition has been created." >> ./verification.txt
	echo "" >> ./verification.txt
else 
	echo "[PASS] A separate /var/log/audit partition has been created." >> ./verification.txt
	echo "" >> ./verification.txt
fi	

#Check for separate partition for /home
checkhome=` grep "[[:space:]]/home[[:space:]]" /etc/fstab`
if [ -z "$checkhome" ]
then
	echo "[FAILED] Please ensure that a separate /home partition has been created." >> ./verification.txt
	echo "" >> ./verification.txt
else 
	 checknodevhome=`grep "[[:space:]]/home[[:space:]]" /etc/fstab | grep nodev`
	 checknodevhome1=`mount | grep "[[:space:]]/home[[:space:]]" | grep nodev`
	
		if [ -z "$checknodevhome" -a -z "$checknodevhome1" ]
		then
			echo "[FAILED] Please ensure that /home is mounted with nodev option." >> ./verification.txt
			echo "" >> ./verification.txt
		elif [ -z "$checknodevhome" -a -n "$checknodevhome1" ]
		then
			echo "[FAILED] Please ensure that /home is mounted persistently with nodev option." >> ./verification.txt
			echo "" >> ./verification.txt
		elif [ -n "$checknodevhome" -a -z "$checknodevhome1" ]
		then
			echo "[FAILED] Please ensure that /home is currently mounted with nodev option." >> ./verification.txt
			echo "" >> ./verification.txt
	else
		echo "[PASS] /home is a separate partition with nodev option." >> ./verification.txt
		echo "" >> ./verification.txt
	fi
fi

#Check if nodev nosuid noexec option is added to RMP
cdcheck=`grep cd /etc/fstab`
if [ -n "$cdcheck" ]
then
	cdnodevcheck=`grep cdrom /etc/fstab | grep nodev`
	cdnosuidcheck=`grep cdrom /etc/fstab | grep nosuid`
	cdnosuidcheck=`grep cdrom /etc/fstab | grep noexec`
	if [ -z "$cdnosuidcheck" ]
	then
		echo "[FAILED] Please ensure /cdrom is mounted with nodev option." >> ./verification.txt
		echo "" >> ./verification.txt	
	elif [ -z "$cdnosuidcheck" ]
	then
		echo "[FAILED] Please ensure /cdrom is mounted with nosuid option." >> ./verification.txt
		echo "" >> ./verification.txt
	elif [ -z "$cdnosuidcheck" ]
	then
		echo "[FAILED] Please ensure /cdrom is mounted with noexec option." >> ./verification.txt
		echo "" >> ./verification.txt
	else
		echo "[PASS] /cdrom is a mounted with nodev, nosuid, noexec option." >> ./verification.txt
		echo "" >> ./verification.txt
	fi
else
	echo "[PASS] /cdrom is not mounted." >> ./verification.txt
fi
 
#Check for sticky bit on all world-writable directories
checkstickybit=`df --local -P | awk {'if (NR1=1) print $6'} | xargs -l '{}' -xdev -type d \(--perm -0002 -a ! -perm -1000 \) 2> /dev/null`
if [ -n "$checkstickybit" ]
then
	echo "[FAILED] Please ensure that Sticky bit is set on all world-writable directories." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS] Sticky bit is set on all world-writable directories." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if mounting of legacy filesystems is disabled
checkcramfs=`/sbin/lsmod | grep cramfs`
checkfreevxfs=`/sbin/lsmod | grep freevxfs`
checkjffs2=`/sbin/lsmod | grep jffs2`
checkhfs=`/sbin/lsmod | grep hfs`
checkhfsplus=`/sbin/lsmod | grep hfsplus`
checksquashfs=`/sbin/lsmod | grep squashfs`
checkudf=`/sbin/lsmod | grep udf`

if [ -n "$checkcramfs" -o -n "$checkfreevxfs" -o -n "$checkjffs2" -o -n "$checkhfs" -o -n "$checkhfsplus" -o -n "$checksquashfs" -o -n "$checkudf" ]
then
	echo "[FAILED] Please ensure that all legacy file systems are disabled i.e. cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs and udf." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS] All legacy file systems are disabled i.e. cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs and udf." >> ./verification.txt
	echo "" >> ./verification.txt
fi

echo "--LEGACY SERVICES--" >> ./verification.txt
services=( "telnet" "telnet-server" "rsh-server" "rsh" "ypserv" "ypbind" "tftp" "tftp-server" "xinetd" )

count=1
for eachservice in ${services[*]}
do 
	yum -q list installed $eachservice &>/dev/null && echo "[FAILED] Please ensure that $eachservice is not installed." >> ./verification.txt || echo "[PASS] $eachservice is not installed." >> ./verification.txt
	echo "" >> ./verification.txt
	((count++))
done 	

#Check if some services are disabled 
chkservices=( "chargen-stream" "daytime-dgram" "daytime-stream" "echo-dgram" "echo-stream" "tcpmux-server" ) 

for eachchkservice in ${chkservices[*]}
do 
	checkxinetd=`yum list xinetd | grep "Available Packages"`
	if [ -n "$checkxinetd" ]
	then
		echo "Xinetd is not installed, hence $eachchkservice is not installed." >> ./verification.txt
		((count++))
	else
		checkchkservices=`chkconfig --list $eachchkservice | grep "off"`
		if [ -n "$checkchkservices" ]
		then 
			echo "[PASS] $eachchkservice is not active as recommended." >> ./verification.txt
			((count++))
		else 
			echo "[FAILED] Please ensure that $eachchkservice is not active." >> ./verification.txt
			((count++))
		fi
	fi
done

echo "" >> ./verification.txt

echo "--SPECIAL PURPOSE SERVICES--" >> ./verification.txt

checkumask=`grep ^umask /etc/sysconfig/init`

if [ "$checkumask" == "umask 027" ]
then 
	echo "[PASS]/etc/sysconfig/init umask is set to 027 as recommended." >> ./verification.txt
	echo "" >> ./verification.txt
else 
	echo "[FAILED] Please ensure that /etc/sysconfig/init umask is set to 027." >> ./verification.txt
	echo "" >> ./verification.txt
fi

checkxsystem=`ls -l /etc/systemd/system/default.target | grep graphical.target` #Must return empty
checkxsysteminstalled=`rpm  -q xorg-x11-server-common`	#Must return something
	
if [ -z "$checkxsystem" -a -z "$checkxsysteminstalled" ]
then 
	echo "[FAILED] Please ensure that Xorg-x11-server-common is not installed." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ -z "$checkxsystem" -a -n "$checkxsysteminstalled" ]
then
	echo "[PASS] Xorg-x11-server-common is not installed and is not the default graphical interface." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ -n "$checkxsystem" -a -z "$checkxsysteminstalled" ]
then
	echo "[FAILED] Xorg-x11-server-common is not installed but please ensure that it is not the default graphical interface." >> ./verification.txt
	echo "" >> ./verification.txt
else 
	echo "[FAILED] Please ensure that Xorg-x11-server-common is not installed and is not the default graphical interface." >> ./verification.txt
	echo "" >> ./verification.txt
fi

checkavahi=`systemctl status avahi-daemon | grep inactive`
checkavahi1=`systemctl status avahi-daemon | grep disabled`
if [ -n "$checkavahi" -a -n "$checkavahi1" ]
then 
	echo "[PASS] Avahi-daemon is inactive and disabled as recommended." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ -n "$checkavahi" -a -z "$checkavahi1" ]
then 
	echo "[FAILED] Avahi-daemon is inactive but please ensure that it is also disabled." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ -z "$checkavahi" -a -n "$checkavahi1" ]
then 
	echo "[FAILED] Avahi-daemon is disabled but please ensure that it is also inactive." >> ./verification.txt
	echo "" >> ./verification.txt
else 
	echo "[FAILED] Please ensure that Avahi-daemon is inactive and disabled." >> ./verification.txt
	echo "" >> ./verification.txt
fi

checkcups=`systemctl status cups | grep inactive`
checkcups1=`systemctl status cups | grep disabled`
	
if [ -n "$checkcups" -a -n "$checkcups1" ]
	then 
		echo "[PASS] Cups is inactive and disabled as recommended." >> ./verification.txt
		echo "" >> ./verification.txt
	elif [ -n "$checkcups" -a -z "$checkcups1" ]
	then 
		echo "[FAILED] Cups is inactive but please ensure that it is disabled." >> ./verification.txt
		echo "" >> ./verification.txt
	elif [ -z "$checkcups" -a -n "$checkcups1" ]
	then 
		echo "[FAILED] Cups is disabled but please ensure that it is inactive." >> ./verification.txt
		echo "" >> ./verification.txt
	else 
		echo "[FAILED] Please ensure that Cups is inactive and disabled." >> ./verification.txt
		echo "" >> ./verification.txt
	fi


checkyumdhcp=`yum list dhcp | grep "Available Packages" `
checkyumdhcpactive=`systemctl status dhcp | grep inactive `
checkyumdhcpenable=`systemctl status dhcp | grep disabled `
if [ -n "$checkyumdhcp" ]
then 
	echo "[PASS] DHCP is not installed as recommended." >> ./verification.txt
else 
	if [ -z "$checkyumdhcpactive" -a -z "$checkyumdhcpenable" ]
	then 
		echo "[FAILED] DHCP is active and enabled. Please ensure that DHCP is not installed" >> ./verification.txt
		echo "" >> ./verification.txt
	elif [ -z "$checkyumdhcpactive" -a -n "$checkyumdhcpenable" ]
	then 
		echo "[FAILED] DHCP is disabled but active. Please ensure that DHCP is not installed." >> ./verification.txt
		echo "" >> ./verification.txt
	elif [ -n "$checkyumdhcpactive" -a -z "$checkyumdhcpenable" ]
	then
		echo "[FAILED] DHCP is inactive but enabled. Please ensure that DHCP is not installed." >> ./verification.txt
		echo "" >> ./verification.txt
	else 
		echo "[FAILED] DHCP is inactive and disabled. Please ensure that DHCP is not installed." >> ./verification.txt
		echo "" >> ./verification.txt
	fi
fi

#Check if NTP is configured
checkntp1=`grep "^restrict default kod nomodify notrap nopeer noquery" /etc/ntp.conf`
checkntp2=`grep "^restrict -6 default kod nomodify notrap nopeer noquery" /etc/ntp.conf` 
checkntp3=`grep "^server" /etc/ntp.conf | grep server`
checkntp4=`grep 'OPTIONS="-u ntp:ntp -p /var/run/ntpd.pid"' /etc/sysconfig/ntpd `

if [ -n "$checkntp1" ]
then 
	if [ -n "$checkntp2" ]
	then 
		if [ -n "$checkntp3" ]
			then 
				if [ -n "$checkntp4" ]
				then
					echo "[PASS] NTP has been properly configured." >> ./verification.txt
					echo "" >> ./verification.txt
				else 
					echo "[FAILED] Please ensure that OPTION has been configured in /etc/sysconfig/ntpd." >> ./verification.txt 
					echo "" >> ./verification.txt
				fi
		else
			echo "[FAILED] Please ensure that /etc/ntp.conf has at least one NTP server specified." >> ./verification.txt
			echo "" >> ./verification.txt
		fi
	else 
		echo "[FAILED] Failed to implement restrict -6 default kod nomodify notrap nopeer noquery in /etc/ntp.conf" >> ./verification.txt
		echo "" >> ./verification.txt
	fi
else 
	echo "[FAILED] Failed to implement restrict default kod nomodify notrap nopeer noquery in /etc/ntp.conf" >> ./verification.txt
	echo "" >> ./verification.txt
fi 

#Check if LDAP is removed
checkldapclients=`yum list openldap-clients | grep 'Available Packages'`
checkldapservers=`yum list openldap-servers | grep 'Available Packages'`

if [ -n "checkldapclients" -a -n "checkldapservers" ]
then 
	echo "[PASS] LDAP server and client are both not installed as recommended." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ -n "checkldapclients" -a -z "checkldapservers" ]
then
	echo "[FAILED] Please ensure LDAP server is not installed." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ -z "checkldapclients" -a -n "checkldapservers" ]
then
	echo "[FAILED] Please ensure that LDAP client is not installed." >> ./verification.txt
	echo "" >> ./verification.txt
else 
	echo "[FAILED] Please ensure that both LDAP client and server are not installed." >> ./verification.txt
	echo "" >> ./verification.txt
fi 

#Check if NFS and RPC is disabled
nfsservices=( "nfs-lock" "nfs-secure" "rpcbind" "nfs-idmap" "nfs-secure-server" )

for eachnfsservice in ${nfsservices[*]}
do 
	checknfsservices=`systemctl is-enabled $eachnfsservice | grep enabled`
	if [ -z "$checknfsservices" ]
	then 
		echo "[PASS] $eachnfsservice is disabled as recommended." >> ./verification.txt
	else 
		echo "[FAILED] Please ensure that $eachnfsservice is disabled." >> ./verification.txt
	fi
done 	

echo "" >> ./verification.txt

standardservices=( "named" "vsftpd" "httpd" "sshd" "snmpd") 

for eachstandardservice in ${standardservices[*]}
do 
	checkserviceexist=`systemctl status $eachstandardservice | grep not-found`
	if [ -n "$checkserviceexist" ]
	then
		echo "$eachstandardservice does not exist in the system as recommended." >> ./verification.txt
	else
		checkstandardservices=`systemctl status $eachstandardservice | grep disabled`
		checkstandardservices1=`systemctl status $eachstandardservice | grep inactive`
		if [ -z "$checkstandardservices" -a -z "$checkstandardservices1" ]
		then 
			echo "[FAILED] $eachstandardservice is active and enabled." >> ./verification.txt
		elif [ -z "$checkstandardservices" -a -n "$checkstandardservices1" ]
		then 
			echo "[FAILED] $eachstandardservice is inactive but enabled." >> ./verification.txt
		elif [ -n "$checkstandardservices" -a -z "$checkstandardservices1" ]
		then 
			echo "[FAILED] $eachstandardservice is disabled but active." >> ./verification.txt
		else 
			echo "[PASS] $eachstandardservice is disabled and inactive as recommended." >> ./verification.txt
		fi
	fi
done 	

echo "" >> ./verification.txt

#Check if MTA is configured for LOM
checkmailtransferagent=`netstat -an | grep ":25[[:space:]]"`

if [ -n "$checkmailtransferagent" ]
then
	checklistening=`netstat -an | grep LISTEN`
	if [ -n "$checklistening" ]
	then
		checklocaladdress=`netstat -an | grep [[:space:]]127.0.0.1:25[[:space:]] | grep LISTEN`
		if [ -n "$checklocaladdress" ]
		then
			echo "[PASS] Mail Transfer Agent is listening on the loopback address as recommended." >> ./verification.txt
			echo "" >> ./verification.txt
		else
			echo "[FAILED] Please ensure that Mail Transfer Agent is listening on the loopback address." >> ./verification.txt
			echo "" >> ./verification.txt
		fi
	else
		echo "[FAILED] Please ensure that Mail Transfer Agent is in listening mode." >> ./verification.txt
		echo "" >> ./verification.txt
	fi
else
	echo "[FAILED] Mail Transfer Agent is not configured/installed." >> ./verification.txt
	echo "" >> ./verification.txt
fi

echo "--BOOT SETTINGS--" >> ./verification.txt
#Check for the file permissions of /boot/grub2/grub.cfg
checkgrubowner=`stat -L -c "owner=%U group=%G" /boot/grub2/grub.cfg`

if  [ "$checkgrubowner" == "owner=root group=root" ]
then
	checkgrubpermission=`stat -L -c "%a" /boot/grub2/grub.cfg | cut -b 2,3`

	if [ "$checkgrubpermission" == "00" ]
	then
		echo "[PASS] Owner of the /boot/grub2/grub.cfg file: root" >> ./verification.txt
		echo "[PASS] Group owner of the /boot/grub2/grub.cfg file: root" >> ./verification.txt
		echo "[PASS] Permisions for the file /boot/grub2/grub.cfg file has been set correctly." >> ./verification.txt
		echo "" >> ./verification.txt
	else
		echo "[FAILED] Permissions has not been set correctly for the /boot/grub2/grub.cfg file. Please ensure that the permissions has been set correctly." >> ./verification.txt
		echo ""	>> ./verification.txt
	fi

else
	echo "[FAILED] Permissions has not been set correctly for the /boot/grub2/grub.cfg file. Please ensure that both the owner and group owner of the file is root." >> ./verification.txt
	echo ""	>> ./verification.txt
fi

#Check the bootloader password
checkbootloaderuser=`grep "^set superusers" /boot/grub2/grub.cfg`

if [ -z "$checkbootloaderuser" ]
then
	echo "[FAILED] Please ensure that the boot loader is configured with at least one superuser." >> ./verification.txt
	echo "" >> ./verification.txt
else
	checkbootloaderpassword=`grep "^password" /boot/grub2/grub.cfg`

	if [ -z "$checkbootloaderpassword" ]
	then
		echo "[FAILED] Please ensure that the boot loader is configured with a password." >> ./verification.txt
		echo "" >> ./verification.txt
	else
		echo "[PASS] Boot loader is configured with a superuser and password." >> ./verification.txt
		echo "" >> ./verification.txt
	fi
fi

echo "--ADDITIONAL HARDENING--" >> ./verification.txt
#Restrict Core Dumps
checkcoredump=`grep "hard core" /etc/security/limits.conf`
coredumpval="* hard core 0"

if [ "$checkcoredump" == "$coredumpval" ]
then
	checksetuid=`sysctl fs.suid_dumpable`
	setuidval="fs.suid_dumpable = 0"

	if [ "$checksetuid" == "$setuidval" ]
	then
		echo "[PASS] Core dumps are restricted and Setuid programs are prevented from dumping core." >> ./verification.txt
		echo "" >> ./verification.txt
	else
		echo "[FAILED] Please ensure that Setuid programs are prevented from dumping core." >> ./verification.txt
		echo "" >> ./verification.txt
	fi

else
	echo "[FAILED] Please ensure that Core dumps are restricted." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Enable Randomized Virtual Memory Region Placement
checkvirtualran=`sysctl kernel.randomize_va_space`
virtualranval="kernel.randomize_va_space = 2"

if [ "$checkvirtualran" == "$virtualranval" ]
then
	echo "[PASS] Virtual memory is randomized." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[FAILED] Please ensure that the Virtual memory is randomized." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#CONFIGURE RSYSLOG

echo "--RSYSLOG CONFIGURATION--" >> ./verification.txt

#Ensure that rsyslog is installed and enabled
checkrsyslog=`rpm -q rsyslog | grep "^rsyslog"`

if [ -n "$checkrsyslog" ]
then
	checkrsysenable=`systemctl is-enabled rsyslog`

	if [ "$checkrsysenable" == "enabled" ]
	then
		echo "[PASS]Rsyslog is installed and enabled." >> ./verification.txt
		echo "" >> ./verification.txt
	else
		echo "[FAILED] Please ensure that Rsyslog is enabled." >> ./verification.txt
		echo "" >> ./verification.txt
	fi

else
	echo "[FAILED] Please ensure that Rsyslog is installed." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Configure /etc/rsyslog.conf
checkvarlogmessageexist=`ls -l /var/log/ | grep messages`

if [ -n "$checkvarlogmessageexist" ]
then
	checkvarlogmessageown=`ls -l /var/log/messages | cut -d ' ' -f3,4`

	if [ "$checkvarlogmessageown" == "root root" ]
	then
		checkvarlogmessagepermit=`ls -l /var/log/messages | cut -d ' ' -f1`

		if [ "$checkvarlogmessagepermit" == "-rw-------." ]
		then
			checkvarlogmessage=`grep /var/log/messages /etc/rsyslog.conf`

			if [ -n "$checkvarlogmessage" ]
			then
				checkusermessage=`grep /var/log/messages /etc/rsyslog.conf | grep "^auth,user.*"`

				if [ -n "$checkusermessage" ]
				then
					echo "[PASS] Owner, group owner, permissions, facility are configured correctly for /var/log/messages and messages logging is set." >> ./verification.txt
				else
					echo "[FAILED] Facility is not configured correctly: /var/log/messages" >> ./verification.txt
				fi

			else
				echo "[FAILED] Please ensure that the messages logging is not set" >> ./verification.txt
			fi

		else
			echo "[FAILED] Please ensure that the permissions of the /var/log/messages file is configured correctly." >> ./verification.txt
		fi

	else
		echo "[FAILED] Please ensure that the owner and group owner of the /var/log/message file is configured correctly."
	fi

else
	echo "[FAILED] /var/log/messages file does not exist."
fi

#Check for /var/log/kern.log
checkvarlogkernexist=`ls -l /var/log/ | grep kern.log`

if [ -n "$checkvarlogkernexist" ]
then
	checkvarlogkernown=`ls -l /var/log/kern.log | cut -d ' ' -f3,4`

	if [ "$checkvarlogkernown" == "root root" ]
	then
		checkvarlogkernpermit=`ls -l /var/log/kern.log | cut -d ' ' -f1`

		if [ "$checkvarlogkernpermit" == "-rw-------." ]
		then
			checkvarlogkern=`grep /var/log/kern.log /etc/rsyslog.conf`

			if [ -n "$checkvarlogkern" ]
			then
				checkuserkern=`grep /var/log/kern.log /etc/rsyslog.conf | grep "^kern.*"`

				if [ -n "$checkuserkern" ]
				then
					echo "[PASS] Owner, group owner, permissions, facility are configured for the /var/log/kern.log file correctly; kern.log logging is set." >> ./verification.txt
				else
					echo "[FAILED] Facility is not configured correctly: /var/log/kern.log"
				fi

			else
				echo "[FAILED] Please ensure that kern.log logging is set." >> ./verification.txt
			fi

		else
			echo "[FAILED] Please ensure that the permissions of /var/log/kern.log file is configured correctly." >> ./verification.txt
		fi

	else
		echo "[FAILED] Please ensure that the owner and group owner of /var/log/kern.log file is configured correctly." >> ./verification.txt
	fi

else
	echo "[FAILED] The /var/log/kern.log file does not exist." >> ./verification.txt
fi

checkvarlogdaemonexist=`ls -l /var/log/ | grep daemon.log`

if [ -n "$checkvarlogdaemonexist" ]
then
	checkvarlogdaemonown=`ls -l /var/log/daemon.log | cut -d ' ' -f3,4`

	if [ "$checkvarlogdaemonown" == "root root" ]
	then
		checkvarlogdaemonpermit=`ls -l /var/log/daemon.log | cut -d ' ' -f1`

		if [ "$checkvarlogdaemonpermit" == "-rw-------." ]
		then
			checkvarlogdaemon=`grep /var/log/daemon.log /etc/rsyslog.conf`

			if [ -n "$checkvarlogdaemon" ]
			then
				checkuserdaemon=`grep /var/log/daemon.log /etc/rsyslog.conf | grep "^daemon.*"`

				if [ -n "$checkuserdaemon" ]
				then
					echo "[PASS] Owner, group owner, permissions, facility for the /var/log/daemon.log are configured correctly; daemon.log logging is set." >> ./verification.txt
				else
					echo "[FAILED] Facility is not configured correctly: /var/log/daemon.log" >> ./verification.txt
				fi

			else
				echo "[FAILED] Please ensure that daemon.log logging is set." >> ./verification.txt
			fi

		else
			echo "[FAILED] Please ensure that the permissions for the /var/log/daemon.log file is configured correctly." >> ./verification.txt
		fi

	else
		echo "[FAILED] Please ensure that the owner and group owner of the /var/log/daemon.log file is configured correctly." >> ./verification.txt
	fi

else
	echo "[FAILED] /var/log/daemon.log file does not exist." >> ./verification.txt
fi

checkvarlogsyslogexist=`ls -l /var/log/ | grep syslog.log`

if [ -n "$checkvarlogsyslogexist" ]
then
	checkvarlogsyslogown=`ls -l /var/log/syslog.log | cut -d ' ' -f3,4`

	if [ "$checkvarlogsyslogown" == "root root" ]
	then
		checkvarlogsyslogpermit=`ls -l /var/log/syslog.log | cut -d ' ' -f1`

		if [ "$checkvarlogsyslogpermit" == "-rw-------." ]
		then
			checkvarlogsyslog=`grep /var/log/syslog.log /etc/rsyslog.conf`

			if [ -n "$checkvarlogsyslog" ]
			then
				checkusersyslog=`grep /var/log/syslog.log /etc/rsyslog.conf | grep "^syslog.*"`

				if [ -n "$checkusersyslog" ]
				then
					echo "[PASS] Owner, group owner, permissions, facility of the file /var/log/syslog are configured correctly; syslog.log logging is set." >> ./verifcation.txt

				else
					echo "[FAILED] Facility is not configured correctly: /var/log/syslog" >> ./verification.txt
				fi

			else
				echo "[FAILED] Please ensure that syslog.log logging is set." >> ./verification.txt
			fi

		else
			echo "[FAILED] Please ensure that the permissions of the /var/log/syslog file is configured correctly." >> ./verification.txt
		fi

	else
		echo "[FAILED] Please ensure that the owner and group owner of /var/log/syslog file is configured correctly." >> ./verification.txt
	fi

else
	echo "[FAILED] /var/log/syslog.log file does not exist." >> ./verification.txt
fi

checkvarlogunusedexist=`ls -l /var/log/ | grep unused.log`

if [ -n "$checkvarlogunusedexist" ]
then
	checkvarlogunusedown=`ls -l /var/log/unused.log | cut -d ' ' -f3,4`

	if [ "$checkvarlogunusedown" == "root root" ]
	then
		checkvarlogunusedpermit=`ls -l /var/log/unused.log | cut -d ' ' -f1`

		if [ "$checkvarlogunusedpermit" == "-rw-------." ]
		then
			checkvarlogunused=`grep /var/log/unused.log /etc/rsyslog.conf`

			if [ -n "$checkvarlogunused" ]
			then
				checkuserunused=`grep /var/log/unused.log /etc/rsyslog.conf | grep "^lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.*"`

				if [ -n "$checkuserunused" ]
				then
					echo "[PASS] Owner, group owner, permissions, facility of the /var/log/unused.log are configured correctly; unused.log logging is set." >> ./verification.txt
					echo "" >> ./verification.txt
				else
					echo "[FAILED] Facility is not configured correctly: /var/log/unused.log" >> ./verification.txt
					echo "" >> ./verificaion.txt
				fi

			else
				echo "[FAILED] Please ensure that the unused.log logging is set." >> ./verification.txt
				echo "" >> ./verification.txt
			fi

		else
			echo "[FAILED] Please ensure that the permissions of the /var/log/unused.log file is configured correctly." >> ./verification.txt
			echo "" >> ./verification.txt
		fi

	else
		echo "[FAILED] Please ensure that the owner and group owner of the /var/log/unused.log file is configured correctly." >> ./verification.txt
		echo "" >> ./verificaion.txt
	fi

else
	echo "[FAILED] /var/log/unused.log file does not exist." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Accept Remote rsyslog Messages only on designated log hosts
checkrsysloglis=`grep '^$ModLoad imtcp.so' /etc/rsyslog.conf`
checkrsysloglis1=`grep '^$InputTCPServerRun' /etc/rsyslog.conf`

if [ -z "$checkrsysloglis" -o -z "$checkrsysloglis1" ]
then
	echo "[FAILED] Please ensure that Rsyslog is listening for remote messages." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS]Rsyslog is listening for remote messages." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Configuring system accounting
echo "--SYSTEM ACCOUNTING--" >> ./verification.txt

checklogstoragesize=`grep max_log_file[[:space:]] /etc/audit/auditd.conf | awk '{print $3}'`

if [ "$checklogstoragesize" == 5 ]
then
	echo "[PASS] Maximum size of audit log files is configured correctly." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[FAILED] Please ensure that the maximum size of audit log files is configured correctly." >> ./verification.txt
	echo "" >> ./verification.txt
fi

checklogfileaction=`grep max_log_file_action /etc/audit/auditd.conf | awk '{print $3}'`
 
if [ "$checklogfileaction" == keep_logs ]
then
	echo "[PASS] Action of the audit log file is configured correctly."
	echo "" >> ./verification.txt
else
	echo "[FAILED] Please ensure that the Action of the audit log file is configured correcly." >> ./verification.txt
	echo "" >> ./verification.txt
fi

checkspaceleftaction=`grep space_left_action /etc/audit/auditd.conf | awk '{print $3}'`

if [ "$checkspaceleftaction" == email ]
then
	checkactionmailacc=`grep action_mail_acct /etc/audit/auditd.conf | awk '{print $3}'`

	if [ "$checkactionmailacc" == root ]
	then
		checkadminspaceleftaction=`grep admin_space_left_action /etc/audit/auditd.conf | awk '{print $3}'`
		
		if [ "$checkadminspaceleftaction" == halt ]
		then
			echo "[PASS] Auditd is correctly configured to notify the administrator and halt the system when audit logs are full." >> ./verification.txt
			echo "" >> ./verification.txt
		else
			echo "[FAILED] Auditd is not configured to halt the system when audit logs are full." >> ./verificaion.txt
			echo "" >> ./verification.txt
		fi

	else
		echo "[FAILED] Auditd is not configured to notify the administrator when audit logs are full." >> ./verification.txt
		echo "" >> ./verificaion.txt
	fi

else
	echo "[FAILED] Auditd is not configured to notify the administrator by email when audit logs are full." >> ./verification.txt
	echo "" >> ./verification.txt
fi

checkauditdservice=`systemctl is-enabled auditd`

if [ "$checkauditdservice" == enabled ]
then
	echo "[PASS] Auditd is enabled." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[FAILED] Please ensure that Auditd is enabled." >> ./verification.txt
	echo "" >> ./verification.txt
fi

eckgrub=$(grep "linux" /boot/grub2/grub.cfg | grep "audit=1") 

if [ -z "$checkgrub" ]
then
	echo "[FAILED] Please ensure that Prior Start-Up is enabled." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS] Prior Start-Up is enabled." >> ./verification.txt
	echo "" >> ./verification.txt
fi

checksystem=`uname -m | grep "64"`
checkmodifydatetimeadjtimex=`egrep 'adjtimex' /etc/audit/audit.rules`

if [ -z "$checksystem" ]
then
	if [ -z "$checkmodifydatetimeadjtimex" ]
	then
        	echo "[FAILED] 32-bit system: Please ensure that Adjtimex is configured" >> ./verification.txt

	else
		echo "[PASS] 32-bit system: Adjtimex is configured" >> ./verification.txt
	fi

else
	if [ -z "$checkmodifydatetimeadjtimex" ]
	then
        	echo "[FAILED] 64-bit system: Please ensure that Adjtimex is configured" >> ./verification.txt

	else
		echo "[PASS] 64-bit system: Adjtimex is configured" >> ./verification.txt
	fi
fi

checkmodifydatetimesettime=`egrep 'settimeofday' /etc/audit/audit.rules`

if [ -z "$checksystem" ]
then

	if [ -z "$checkmodifydatetimesettime" ]
	then
        	echo "[FAILED] Please ensure that the Settimeofday function is configured." >> ./verification.txt
	else
        	echo "[PASS] Settimeofday is configured." >> ./verification.txt
	fi

else
	if [ -z "$checkmodifydatetimesettime" ]
	then
        	echo "[FAILED] Plase ensure that the Settimeofday function is configured." >> ./verification.txt
	else
        	echo "[PASS] Settimeofday is configured." >> ./verification.txt
	fi

fi

checkmodifydatetimeclock=`egrep 'clock_settime' /etc/audit/audit.rules`

if [ -z "$checkmodifydatetimeclock" ]
then
       	echo "[FAILED] Please ensure that the Clock Settime is configured." >> ./verification.txt
	echo "" >> ./verification.txt
else
       	echo "[PASS] Clock Settime is configured." >> ./verification.txt
	echo "" >> ./verification.txt
fi

checkmodifyusergroupinfo=`egrep '\/etc\/group' /etc/audit/audit.rules`

if [ -z "$checkmodifyusergroupinfo" ]
then
        echo "[FAILED] The recording of modifcations made to the /etc/group is not configured." >> ./verification.txt
else
        echo "[PASS] The recording of modifications made to the /etc/group is configured." >> ./verification.txt
fi

checkmodifyuserpasswdinfo=`egrep '\/etc\/passwd' /etc/audit/audit.rules`

if [ -z "$checkmodifyuserpasswdinfo" ]
then
        echo "[FAILED] The recording of modifications made to the /etc/passwd file is not configured." >> ./verification.txt
else
        echo "[PASS] The recording of modifications made to the /etc/passwd file is configured." >> ./verification.txt
fi

checkmodifyusergshadowinfo=`egrep '\/etc\/gshadow' /etc/audit/audit.rules`

if [ -z "$checkmodifyusergshadowinfo" ]
then
        echo "[FAILED] The recording of modifications made to the /etc/gshadow file is not configured." >> ./verification.txt
else
        echo "[PASS] The recording of modifications made to the /etc/gshadow file is configured." >> ./verification.txt
fi

checkmodifyusershadowinfo=`egrep '\/etc\/shadow' /etc/audit/audit.rules`

if [ -z "$checkmodifyusershadowinfo" ]
then
        echo "[FAILED] The recording of modifications made to the /etc/shadow file is not configured." >> ./verification.txt

else
        echo "[PASS] The recording of modifications made to the /etc/shadow is configured." >> ./verification.txt
fi

checkmodifyuseropasswdinfo=`egrep '\/etc\/security\/opasswd' /etc/audit/audit.rules`

if [ -z "$checkmodifyuseropasswdinfo" ]
then
        echo "[FAILED] The recording of modifications made to the /etc/security/opasswd is not configured." >> ./verification.txt
	echo "" >> ./verification.txt
else
        echo "[PASS] The recording of modifications made to the /etc/security/opasswd file is configured." >> ./verification.txt
	echo "" >> ./verification.txt
fi

checksystem=`uname -m | grep "64"`
checkmodifynetworkenvironmentname=`egrep 'sethostname|setdomainname' /etc/audit/audit.rules`

if [ -z "$checksystem" ]
then
	if [ -z "$checkmodifynetworkenvironmentname" ]
	then
        	echo "[FAILED] 32-bit system: Sethostname and setdomainname is not configured" >> ./verification.txt
		echo "" >> ./verification.txt
	else
		echo "[PASS] 32-bit system: Sethostname and setdomainname is configured" >> ./verification.txt
		echo "" >> ./verification.txt
	fi

else
	if [ -z "$checkmodifynetworkenvironmentname" ]
	then
        	echo "[FAILED] 64-bit system: Sethostname and setdomainname is not configured" >> ./verification.txt
		echo "" >> ./verification.txt
	else
		echo "[PASS] 64-bit system: Sethostname and setdomainname is configured" >> ./verification.txt
		echo "" >> ./verification.txt
	fi

fi

checkmodifynetworkenvironmentissue=`egrep '\/etc\/issue' /etc/audit/audit.rules`

if [ -z "$checkmodifynetworkenvironmentissue" ]
then
       	echo "[FAILED] The /etc/issue is not configured and monitored." >> ./verification.txt
else
       	echo "[PASS] /etc/issue has been configured as recommended." >> ./verification.txt
fi

checkmodifynetworkenvironmenthosts=`egrep '\/etc\/hosts' /etc/audit/audit.rules`

if [ -z "$checkmodifynetworkenvironmenthosts" ]
then
       	echo "[FAILED] The /etc/hosts is not configured and monitored." >> ./verification.txt
else
       	echo "[PASS] /etc/hosts is configured as recommended." >> ./verification.txt
fi

checkmodifynetworkenvironmentnetwork=`egrep '\/etc\/sysconfig\/network' /etc/audit/audit.rules`

if [ -z "$checkmodifynetworkenvironmentnetwork" ]
then
       	echo "[FAILED] The /etc/sysconfig/network is not configured and monitored." >> ./verification.txt
	echo "" >> ./verification.txt
else
       	echo "[PASS] /etc/sysconfig/network is configured." >> ./verification.txt
	echo "" >> ./verification.txt
fi

checkmodifymandatoryaccesscontrol=`grep \/etc\/selinux /etc/audit/audit.rules`

if [ -z "$checkmodifymandatoryaccesscontrol" ]
then
	echo "[FAILED] Recording of modified system's mandatory access controls events is not configured." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS] Recording of modified system's mandatory access controls events is configured." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if login/login events are monitored
chklogins=`grep logins /etc/audit/audit.rules`
loginfail=`grep "\-w /var/log/faillog -p wa -k logins" /etc/audit/audit.rules`
loginlast=`grep "\-w /var/log/lastlog -p wa -k logins" /etc/audit/audit.rules`
logintally=`grep "\-w /var/log/tallylog -p wa -k logins" /etc/audit/audit.rules`

if [ -z "$loginfail" -o -z "$loginlast" -o -z "$logintally" ]
then
        echo "[FAILED] Please ensure that login and logout events recorded." >> ./verification.txt
	echo "" >> ./verification.txt
else
        echo "[PASS] Login and logout events recorded as recommended." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if session initiation information is collected
chksession=`egrep 'wtmp|btmp|utmp' /etc/audit/audit.rules`
sessionwtmp=`egrep "\-w /var/log/wtmp -p wa -k session" /etc/audit/audit.rules`
sessionbtmp=`egrep "\-w /var/log/btmp -p wa -k session" /etc/audit/audit.rules`
sessionutmp=`egrep "\-w /var/run/utmp -p wa -k session" /etc/audit/audit.rules`

if [ -z "$sessionwtmp" -o -z "$sessionbtmp" -o -z "sessionutmp" ]
then
        echo "[FAILED] Please ensure that session initiation information is collected." >> ./verification.txt
	echo "" >> ./verification.txt
else
        echo "[PASS] Session initiation information is collected as recommended." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if Discretionary Access Control Permissions Modification Events is collected
chkpermission64=`grep perm_mod /etc/audit/audit.rules`
permission1=`grep "\-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules`
permission2=`grep "\-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
auid!=4294967295 -k perm_mod" /etc/audit/audit.rules`
permission3=`grep "\-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S|chown -F auid>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules`
permission4=`grep "\-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S|chown -F auid>=1000 -F auid!=4294967295 -k perm_mod" /etc/audit/audit.rules`
permission5=`grep "\-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -Fauid!=4294967295 -k perm_mod" /etc/audit/audit.rules`
permission6=`grep "\-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S
fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F
auid!=4294967295 -k perm_mod" /etc/audit/audit.rules`

if [ -z "$permission1" -o -z "$permission2" -o -z permission3 -o -z permission4 -o -z permission5 -o -z permission6 ]
then
        echo "[FAILED] Please ensure that permission modifications is being recorded." >> ./verification.txt
	echo "" >> ./verification.txt
else
        echo "[PASS] Permission modification is being recorded." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if unsuccessful unauthorized access attempts to files is collected
chkaccess=`grep access /etc/audit/audit.rules`
access1=`grep "\-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 - k access" /etc/audit/audit.rules`
access2=`grep "\-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 - k access" /etc/audit/audit.rules`
access3=`grep "\-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 - k access" /etc/audit/audit.rules`
access4=`grep "\-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 - k access" /etc/audit/audit.rules`
access5=`grep "\-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 - k access" /etc/audit/audit.rules`
access6=`grep "\-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 - k access" /etc/audit/audit.rules`

if [ -z "$access1" -o -z "$access2" -o -z "$access3" -o -z "$access4" -o -z "$access5" -o -z "$access6" ]
then
        echo "[FAILED] Please ensure that unsuccesful and unauthorized access attempts to files is being recorded." >> ./verification.txt
	echo "" >> ./verification.txt
else
        echo "[PASS] Unsuccessful and unauthorized attempts to access files is being recorded." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if the use of Privileged Commands is collected
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit-F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' > /tmp/1.log

checkpriviledge=`cat /tmp/1.log`
cat /etc/audit/audit.rules | grep -- "$checkpriviledge" > /tmp/2.log

checkpriviledgenotinfile=`grep -F -x -v -f /tmp/2.log /tmp/1.log`

if [ -n "$checkpriviledgenotinfile" ]
then
	echo "[FAILED] Please ensure Privileged Commands Collection is in audit." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS] Privileged Commands Collection is in audit" >> ./verification.txt
	echo "" >> ./verification.txt
fi

rm /tmp/1.log
rm /tmp/2.log

#Check if Successful File System Mounts is collected
bit64mountb64=`grep "\-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" /etc/audit/audit.rules`
bit64mountb32=`grep "\-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" /etc/audit/audit.rules`
bit32mountb32=`grep "\-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" /etc/audit/audit.rules`

if [ -z "$bit64mountb64" -o -z "$bit64mountb32" -o -z "$bit32mountb32" ]
then
	echo "[FAILED] Please ensure that mount commands is being collected." >> ./verification.txt
	echo "" >> ./verification.txt  
else
	echo "[PASS] Mount commands is being collected." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if File Deletion Events by User is being collected
bit64delb64=`grep "\-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" /etc/audit/audit.rules`
bit64delb32=`grep "\-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" /etc/audit/audit.rules`
bit32delb32=`grep "\-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" /etc/audit/audit.rules`

if [ -z "$bit64delb64" -o -z "$bit64delb32" -o -z "$bit32delb32" ]
then
	echo "[FAILED] Please ensure file deletion events by user is collected." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS] File deletion events by user is being collected." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if Changes made to System Administration Scope is being collected
chkscope=`grep scope /etc/audit/audit.rules`
sudoers='-w /etc/sudoers -p wa -k scope'

if [ -z "$chkscope" -o "$chkscope" != "$sudoers" ]
then
	echo "[FAILED] Modifications made to /etc/sudoers is not collected." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS] Modifications made to /etc/sudoers is collected." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if system administrator actions is being collected
chkadminrules=`grep actions /etc/audit/audit.rules`
adminrules='-w /var/log/sudo.log -p wa -k actions'

if [ -z "$chkadminrules" -o "$chkadminrules" != "$adminrules" ]
then 
	echo "[FAILED] Administrator activity is not being recorded." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS] Administrator activity is being recorded." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if Kernel Module Loading and Unloading is being collected
chkmod1=`grep "\-w /sbin/insmod -p x -k modules" /etc/audit/audit.rules`
chkmod2=`grep "\-w /sbin/rmmod -p x -k modules" /etc/audit/audit.rules`
chkmod3=`grep "\-w /sbin/modprobe -p x -k modules" /etc/audit/audit.rules`
chkmod4=`grep "\-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" /etc/audit/audit.rules`

if [ -z "$chkmod1" -o -z "$chkmod2" -o -z "$chkmod3" -o -z "$chkmod4" ]
then
	echo "[FAILED] Please ensure that Kernel module recording is set." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS] Kernel module recording is set." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if Audit Configuration is made immutable
chkimmute=`grep "^-e 2" /etc/audit/audit.rules`
immute='-e 2'

if [ -z "$chkimmute" -o "$chkimmute" != "$immute" ]
then
	echo "[FAILED] Please ensure that Audit configuration is immutable." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS] Audit configuration is immutable as recommended." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if logrotate is configured
chkrotate1=`grep "/var/log/messages" /etc/logrotate.d/syslog`
chkrotate2=`grep "/var/log/secure" /etc/logrotate.d/syslog`
chkrotate3=`grep "/var/log/maillog" /etc/logrotate.d/syslog`
chkrotate4=`grep "/var/log/spooler" /etc/logrotate.d/syslog`
chkrotate5=`grep "/var/log/boot.log" /etc/logrotate.d/syslog`
chkrotate6=`grep "/var/log/cron" /etc/logrotate.d/syslog`

if [ -z "chkrotate1" -o -z "$chkrotate2" -o -z "$chkrotate3" -o -z "$chkrotate4" -o -z "$chkrotate5" -o -z "$chkrotate6" ]
then
	echo "[FAILED] Please ensure that System logs are being not rotated." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[PASS] System logs are rotated." >> ./verification.txt
	echo "" >> ./verification.txt
fi

echo "--USER ACCOUNTS, GROUPS AND ENVIRONMENT--" >> ./verification.txt
#Check if password expiration date is set
echo "User Accounts, Groups and Environment" >> ./verification.txt
value=$(cat /etc/login.defs | grep "^PASS_MAX_DAYS" | awk '{ print $2 }')

standard=90 

if [ ! $value = $standard ]; then
	echo "[FAILED] Please ensure that passwords will expire in 90 days." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ $value = $standard ]; then
 	echo "[PASS] An expiration date for passwords has been set." >> ./verification.txt
	echo "" >> ./verification.txt
else
 	echo "[ERROR] Please ensure that passwords will expire in 90 days" >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check for the minimum number of days for the next password change
value=$(cat /etc/login.defs | grep "^PASS_MIN_DAYS" | awk '{ print $2 }')

standard=7 

if [ ! $value = $standard ]; then
	echo "[FAILED] Please ensure that a minimum of 7 days has been set for the next password change." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ $value = $standard ]; then
	echo "[PASS] A minimum of 7 days has been set for the next password change." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[ERROR] Please ensure that a minimum of 7 days has been set for the next password change." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if Password Expiring Warning Days has been set
value=$(cat /etc/login.defs | grep "^PASS_WARN_AGE" | awk '{ print $2 }')

standard=7 

if [ ! $value = $standard ]; then
	echo "[FAILED] Please ensure that password expiring warning days has been set." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ $value = $standard ]; then
	echo "[PASS] Password expiring warning days has been set." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[ERROR] Please ensure that password expiring warning days has been set." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if system accounts are disabled
current=$(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") { print $1 }')

if [ -z "$current" ]; then
	echo "[PASS] System Accounts has been disabled." >> ./verification.txt
	echo "" >> ./verification.txt
elif [ ! -z "$current" ]; then
	echo "[FAILED] Please ensure that system accounts has been disabled." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[ERROR] Please ensure that system accounts has been disabled." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check the Default Group for root Account
current=$(grep "^root:" /etc/passwd | cut -f4 -d:)

if [ "$current" == 0 ]; then
        echo "[PASS] The default group for the root account is configured correctly." >> ./verification.txt
	echo "" >> ./verification.txt
else
        echo "[FAILED] Please ensure that the default group for the root account is configured correctly" >> ./verification.txt
	echo "" >> ./verification
fi

#Check if a default umask is set for users 
current=$(egrep -h "\s+umask ([0-7]{3})" /etc/bashrc /etc/profile | awk '{print $2}')

counterUmask=0

for line in ${current}
do
	if [ "${line}" != "077" ] 
	then
       		((counterUmask++))	
	fi
done

if [ ${counterUmask} == 0 ]
then 
	echo "[PASS] A default umask has been configured for subsequent files created." >> ./verification.txt
	echo "" >> ./verification.txt
else     
	echo "[FAILED] Please ensure that a default mask has been configured for subsequent files." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check if Inactive User Accounts are locked
current=$(useradd -D | grep INACTIVE | awk -F= '{print $2}')
if [ "${current}" -le 30 ] && [ "${current}" -gt 0 ]
then
        echo "[PASS] Inactive user accounts has been locked." >> ./verification.txt
	echo "" >> ./verification.txt
else
        echo "[FAILED] Please ensure that user accounts has been locked." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check Password Fields and ensure that they are not empty"
current=$(cat /etc/shadow | awk -F: '($2 == "") { print $1 }')

if [ "$current" = "" ];then
	echo "[PASS] All active accounts have been secured with a password." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[FAILED] Please ensure that all active accounts have been secured with a password." >> ./verification.txt
	echo "" >> ./verification.txt 
fi

#Check and verify no Legacy "+" Entries Exist in /etc/passwd, /etc/shadow and /etc/group files
passwd=$(grep '^+:' /etc/passwd) 
shadow=$(grep '^+:' /etc/shadow)
group=$(grep '^+:' /etc/group)

if [ "$passwd" == "" ]  && [ "$shadow" == "" ] && [ "$group" == "" ];then
	echo "[PASS] The plus character is not present in /etc/passwd, /etc/shadow and /etc/group." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[FAILED] Please ensure that the plus character is not present in /etc/passwd, /etc/shadow and /etc/group." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Verify that no UID 0 accounts exist other than root
current=$(/bin/cat /etc/passwd | /bin/awk -F: '($3 ==0) { print $1 }')

if [ "$current" = "root" ];then
	echo "[PASS] No other accounts has the UID of 0 except for root." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[FAILED] Please ensure that no other accounts has the UID of 0 except for root." >> ./verification/txt
	echo "" >> ./verification.txt
fi

#Check for root PATH Integrity
rootPathCheck=0

#Check for Empty Directory in PATH (::)
if [ "`echo $PATH | grep ::`" != "" ]
then
	#echo "Empty Directory in PATH (::)"
	((rootPathCheck++))
fi

#Check for Trailing : in PATH
if [ "`echo $PATH | grep :$`" != "" ]
then
	#echo "Trailing : in PATH"
	((rootPathCheck++))
fi

p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]
do
	#Check if PATH contains .
        if [ "$1" = "." ]
        then
		#echo "PATH contains ."
		((rootPathCheck++))
		shift
		continue
        fi
	
	#Check if PATH entry is a directory
        if [ -d $1 ]
        then
                dirperm=`ls -ldH $1 | cut -f1 -d" "`
                #Check if Group Write permission is set on directory
		if [ `echo $dirperm | cut -c6` != "-" ]
                then
			#echo "Group Write permission set on directory $1"
			((rootPathCheck++))
                fi
		#Check if Other Write permission is set on directory
                if [ `echo $dirperm | cut -c9` != "-" ]
		then
			#echo "Other Write permission set on directory $1"
			((rootPathCheck++))
                fi
		
		#Check if PATH entry is owned by root
                dirown=`ls -ldH $1 | awk '{print $3}'`
                if [ "$dirown" != "root" ]
                then
                       #echo $1 is not owned by root
			((rootPathCheck++))
                fi
        else
		#echo $1 is not a directory
		((rootPathCheck++))
        fi
	shift
done

if [ ${rootPathCheck} == 0 ]
then
	echo "[PASS] The root path is legitimate." >> ./verification.txt
	echo "" >> ./verification.txt
elif [[ ${check} != 0 ]]
then
	echo "[FAILED] Please ensure that the root path is legitimate." >> ./verification.txt
	echo "" >> ./verification.txt
else
	echo "[ERROR] Please ensure that the root path is legitimate." >> ./verification.txt
	echo "" >> ./verification.txt
fi

#Check Permissions on User Home Directories
intUserAcc="$(/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin"){ print $6 }')"

if [ -z "$intUserAcc" ]
then
        echo "[PASS] There is no interactive user account." >> ./verification.txt
        echo "" >> ./verification.txt
else
        /bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin"){ print $6 }' | while read -r line; do

                echo "Checking user home directory $line" >> ./verification.txt
                permission="$(ls -ld $line)"
                echo "Permission is ${permission:0:10}" >> ./verification.txt
                #Check 6th field 
                if [[ ${permission:5:1} == *"w"* ]]
                then
                        echo "[FAILED] Please ensure that the group does not have write permissions." >> ./verification.txt
                else
                        echo "[PASS] The group does not have write permissions as recommended." >> ./verification.txt
                fi

                #Check 8th field 
                if [[ ${permission:7:1} == "-" ]]
                then
                        echo "[PASS] Others are not given read permissions as recommended." >> ./verification.txt
                else
                        echo "[FAILED] Please ensure that others are not given read permissions." >> ./verification.txt
 		fi

                #Check 9th field
                if [[ ${permission:8:1} == "-" ]]
                then
                        echo "[PASS] Others are not given write permissions as recommended." >> ./verification.txt
                else
                        echo "[FAILED] Please ensure that others are not given write permissions." >> ./verification.txt
                fi

                #Check 10th field
                if [[ ${permission:9:1} == "-" ]]
                then
                        echo "[PASS] Others are not given execute permissions as recommended." >> ./verification.txt
                else
                        echo "[FAILED] Please ensure that others are not given execute permissions." >> ./verification.txt 
                fi
                echo "" >> ./verification.txt
        done
fi

#Check User Dot File Permissions
intUserAcc="$(/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin"){ print $6 }')"

if [ -z "$intUserAcc" ]
then
        echo "[PASS] There is no interactive user account." >> ./verification.txt
        echo "" >> ./verification.txt
else
        /bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin"){ print $6 }' | while read -r line; do

                echo "Checking hidden files in user home directory $line" >> ./verification.txt
                cd $line
                hiddenfiles="$(echo .*)"

                if [ -z "$hiddenfiles" ]
                then
			echo "[PASS] There are no hidden files." >> ~/Desktop/verification.txt
                else
                        for file in ${hiddenfiles[*]}
                        do
                                permission="$(stat -c %A $file)"
                                echo "Checking hidden file $file" >> ~/Desktop/verification.txt 
                                echo "Permission is $permission" >> ~/Desktop/verification.txt

                                #Check 6th field
                                if [[ ${permission:5:1} == *"w"* ]]
                                then
                                        echo "[FAILED] Please ensure that group does not have write permissions." >> ~/Desktop/verification.txt
                                else
                                        echo "[PASS] Group does not have write permissions as recommended." >> ~/Desktop/verification.txt
                                fi

                                #Check 9th field
                                if [[ ${permission:8:1} == *"w"* ]]
                                then
                                        echo "[FAILED] Please ensure that others do not have write permissions." >> ~/Desktop/verification.txt
                                else
                                        echo "[PASS] Others do not have write permissions as recommended." >> ~/Desktop/verification.txt
                                fi
 				echo "" >> ~/Desktop/verification.txt
                        done
                fi
        done
fi

cd ~/Desktop

#Check Existence of and Permissions on User .netrc Files
intUserAcc="$(/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin"){ print $6 }')"

if [ -z "$intUserAcc" ]
then
        echo "[PASS] There is no interactive user account." >> ./verification.txt
        echo "" >> ./verification.txt
else
        /bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin"){ print $6 }' | while read -r line; do
 	echo "Checking user home directory $line" >> ./verification.txt
                permission="$(ls -al $line | grep .netrc)"
                if  [ -z "$permission" ]
                then
                        echo "[PASS] The .netrc file does not exist." >> ./verification.txt
                        echo "" >> ./verification.txt
                else
                        ls -al $line | grep .netrc | while read -r netrc; do
                                echo " $netrc"

                                #Check 5th field
                                if [[ ${netrc:4:6} == "------" ]]
                                then
                                        echo "[PASS] The permissions for the .netrc file has been set correctly." >> ./verification.txt
                                else
                                        echo "[FAILED] Please ensure that the permissions for the .netrc file has been set correctly." >> ./verification.txt
                                fi

                                echo "" >> ./verification.txt
                        done
                fi
        done
fi

#Check for Presence of User .rhosts Files
intUserAcc="$(/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin"){ print $6 }')"

if [ -z "$intUserAcc" ]
then
        echo "[PASS] There is no interactive user account." >> ./verification.txt
        echo "" ./verification.txt
else
        /bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | /bin/awk -F: '($7 != "/sbin/nologin"){ print $6 }' | while read -r line; do
                echo "Checking user home directory $line" >> ./verification.txt
                rhostsfile="$(ls -al $line | grep .rhosts)"

 		if  [ -z "$rhostsfile" ]
                	then
                        	echo "[PASS] There is no .rhosts file." >> ./verification.txt
                        	echo "" >> ./verification.txt
                	else
                        	ls -al $line | grep .rhosts | while read -r rhosts; do
                                for file in $rhosts
                                do
                                        if [[ $file = *".rhosts"* ]]
                                        then
                                                echo " Checking .rhosts file $file"
                                                #check if file created user matches directory user
                                                filecreateduser=$(stat -c %U $line/$file)
                                                if [[ $filecreateduser = *"$line"* ]]
                                                then
                                                        echo "[PASS] $file created user is the same user in the directory." >> ./verification.txt
							echo "" >> ./verification.txt
                                                else
                                                        echo "[FAILED] $file created user is not the same in the directory. This file should be deleted!" >> ./verification.txt
 							echo "" >> ./verification.txt
                                                fi
                                        fi
                                done                    
                        done
                fi
        done
fi

#Check Groups in /etc/passwd

for i in $(cut -s -d: -f4 /etc/passwd | sort -u); do
	grep -q -P "^.*?:x:$i:" /etc/group
	if [ $? -ne 0 ]
	then
		echo "[FAILED] Group $i is referenced by /etc/passwd but does not exist in /etc/group." >> ./verification.txt
	else
		echo "[PASS] Group $i is referenced by /etc/passwd and exist in /etc/group." >> ./verification.txt
	fi
	echo "" >> ./verification.txt
done

#Check That Users Are Assigned Valid Home Directories && Home Directory Ownership is Correct
cat /etc/passwd | awk -F: '{ print $1,$3,$6 }' | while read user uid dir; do

	#checking validity of  user assigned home directories
	if [ $uid -ge 500 -a ! -d"$dir" -a $user != "nfsnobody" ]
	then
		echo "[FAILED] The home directory $dir of user $user does not exist." >> ./verification.txt
	else
		echo "[PASS] The home directory $dir of user $user exist." >> ./verification.txt
	fi

	#checking user home directory ownership
	if [ $uid -ge 500 -a -d"$dir" -a $user != "nfsnobody" ]
	then
		owner=$(stat -L -c "%U" "$dir")
		if [ "$owner" != "$user" ]
		then
			echo "[FAILED] The home directory ($dir) of user $user is owned by $owner." >> ./verification.txt
		else

			echo "[PASS] Then home directory ($dir) of user $user is owned by $owner." >> ./verification.txt
		fi
	fi
	echo "" >> ./verification.txt
done

#Check for Duplicate UIDs
/bin/cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c | while read x; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]
	then
		users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | /user/bin/xargs`
		echo "[FAILED] Duplicate UID $2: ${users}" >> ./verification.txt
	else
		echo "[PASS] There is no duplicate UID $2" >> ./verification.txt 
	fi
done
echo "" >> ./verification.txt

#Check for Duplicate GIDs
/bin/cat /etc/group | /bin/cut -f3 -d"." | /bin/sort -n | /usr/bin/uniq -c | while read x; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]
	then
		grp=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
		echo "[FAILED] Duplicate GID $2: $grp" >> ./verification.txt
	else
		echo "[PASS] There is no duplicated GID $2" >> ./verification.txt
	fi
done
echo "" >> ./verification.txt

#Check that reserved UIDs are assigned to only system accounts

systemaccount=(root bin daemon adm lp sync shutdown halt mail news uucp operator games gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump systemd-network tss radvd [51]=qemu)

nameCounter=0
rUIDCounter=0
systemNameFile="/etc/passwd"
while IFS=: read -r f1 f2 f3 f4 f5 f6 f7
do
	if [[ $f3 -lt 500 ]]
	then
		for i in ${systemaccount[*]}
		do
			if [[ $f1 == $i ]]
			then
				nameCounter=$((nameCounter+1))
			else
				nameCounter=$((nameCounter+0))
			fi
		done

		if [[ $nameCounter < 1 ]]
		then
			rUIDCounter=$((rUIDCounter+1))
			echo "[FAILED] User '$f1' is not a system account but has a reserved UID of $f3." >> ./verification.txt
		fi
		nameCounter=0
	fi
done <"$systemNameFile"

if [[ $rUIDCounter == 0 ]]
then
	echo "[PASS] No reserved UID has been set for non-system accounts." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Duplicate User Name
uNameCounter=0
cat /etc/passwd | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c | while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
		uNameCounter=$((uNameCounter+1))
		echo "[FAILED] There is/are $1 duplicate user name titled '$2' found in the system and its respective UIDs are ${uids}." >> ./verification.txt
	fi
done
if [[ $uNameCounter == 0 ]]
then
	echo "[PASS] There are not duplicate usernames." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Duplicate Group Names
gNameCounter=0
cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c | 
while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
		gNameCounter=$((gNameCounter+1))
		echo "[FAILED] There are/is $1 duplicate group name(s) titled '$2' found in the system and its respective UIDs are ${gids}." >> ./verification.txt
	fi
done
if [[ $gNameCounter == 0 ]]
then
	echo "[PASS] There are no duplicate group names." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check for presence of user .forward files
fFileCounter=0
for dir in `/bin/cat /etc/passwd | /bin/awk -F: '{ print $6 }'`; do
	if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then 
		fFileCounter=$((fFileCounter+1))
		echo "[FAILED] .forward file titled '$dir/.forward' is found in the system." >> ./verification.txt
	fi
done
echo "" >> ./verification.txt
if [[ fFileCounter == 0 ]]
then
	echo "[PASS] .forware file not found in system." >> ./verification.txt 
fi

echo "" >> ./verification.txt

#Check is warning banner for standard login services is set
echo "--WARNING BANNERS--" >> ./verification.txt
current=$(cat /etc/motd)
standard="WARNING: UNAUTHORIZED USERS WILL BE PROSECUTED!"

if [ "$current" == "$standard" ]; then
        echo "[PASS] Warning banner for standard login services is set." >> ./verification.txt
else
       	echo "[FAILED] Please ensure that a warning banner for standard login services is set." >> ./verification.txt
fi

#Check if OS information is removed from login warning banners
current1=$(egrep '(\\v|\\r|\\m|\\s)' /etc/issue)
current2=$(egrep '(\\v|\\r|\\m|\\s)' /etc/motd)
current3=$(egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net)

string1="\\v"
string2="\\r"
string3="\\m"
string4="\\s"

if [[ $current1 =~ $string1 || $current1 =~ $string2 || $current1 = ~$string3 || $current1 =~ $string4 ]]; then
        echo "[FAILED] Please ensure that OS Information cannot be found in /etc/issue." >> ./verification.txt
else
        echo "[PASS] /etc/issue has no issues." >> ./verification.txt
fi

if [[ $current2 =~ $string1 || $current2 =~ $string2 || $current2 = ~$string3 || $current2 =~ $string4 ]]; then
        echo "[FAILED] Please ensure that the OS Information cannot be found in /etc/motd." >> ./verification.txt
else
        echo "[PASS]/etc/motd has no issues." >> ./verification.txt
fi

if [[ $current3 =~ $string1 || $current3 =~ $string2 || $current3 = ~$string3 || $current4 =~ $string4 ]]; then
        echo "[FAILED] OS Information found in /etc/issue.net." >> ./verification.txt
else
        echo "[PASS] /etc/issue.net has no issues." >> ./verification.txt
fi

echo "" >> ./verification.txt
echo "--CRON AND ANACRON--" >> ./verification.txt 
#Check whether Anacron Daemon is enabled or not
if rpm -q cronie-anacron > /dev/null
then
	echo "[PASS] Anacron Daemon has been installed." >> ./verification.txt
else
	echo "[FAILED] Please ensure that you have Anacron Daemon has been installed." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if Crond Daemon is enabled
checkCronDaemon=$(systemctl is-enabled crond 2>/dev/null)
if [[ $checkCronDaemon = "enabled" ]]
then
	echo "[PASS] Crond Daemon has been enabled." >> ./verification.txt
else
	echo "[FAILED] Please ensure that you have enabled crond Daemon." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if the correct permissions is configured for /etc/anacrontab
anacrontabFile="/etc/anacrontab"
if [ -e "$anacrontabFile" ]
then
	echo "[PASS] The Anacrontab file ($anacrontabFile) exists." >> ./verification.txt
	
	anacrontabPerm=$(stat -c "%a" "$anacrontabFile")
	anacrontabRegex="^[0-7]00$"
	if [[ $anacrontabPerm =~ $anacrontabRegex ]]
	then
		echo "[PASS] Permissions has been set correctly for $anacrontabFile." >> ./verification.txt
	else
		echo "[FAILED] Ensure that the permissions has been set correctly for $anacrontabFile." >> ./verification.txt
	fi

	anacrontabOwn=$(stat -c "%U" "$anacrontabFile")
	if [[ $anacrontabOwn == "root" ]]
	then
		echo "[PASS] Owner of the file ($anacrontabFile): $anacrontabOwn" >> ./verification.txt
	else
		echo "[FAILED] Owner of the file ($anacrontabFile): $anacrontabOwn. Please ensure that the owner of the file is root instead." >> ./verification.txt
	fi

	anacrontabGrp=$(stat -c "%G" "$anacrontabFile")
	if [[ $anacrontabGrp == "root" ]]
	then
		echo "[PASS] Group owner of the file ($anacrontabFile): $anacrontabGrp" >> ./verification.txt
	else
		echo "[FAILED] Group owner of the file ($anacrontabFile): $anacrontabGrp. Please ensure that the group owner is root instead." >> ./verification.txt
	fi
else
	echo "[FAILED] The Anacrontab file does not exist. Please ensure that you have Anacron Daemon installed." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if the correct permissions has been configured for /etc/crontab
crontabFile="/etc/crontab"
if [ -e "$crontabFile" ]
then
	crontabPerm=$(stat -c "%a" "$crontabFile")
	crontabRegex="^[0-7]00$"
	if [[ $crontabPerm =~ $crontabRegex ]]
	then
		echo "[PASS] Permissions has been set correctly for $crontabFile." >> ./verification.txt
	else
		echo "[FAILED] Ensure that the permissions has been set correctly for $crontabFile." >> ./verification.txt
	fi

	crontabOwn=$(stat -c "%U" "$crontabFile")
	if [[ $crontabOwn == "root" ]]
	then
		echo "[PASS] Owner of the file ($crontabFile): $crontabOwn" >> ./verification.txt
	else
		echo "[FAILED] Owner of the file ($crontabFile): $crontabOwn. Please ensure that the owner of the file is root instead." >> ./verification.txt
	fi

	crontabGrp=$(stat -c "%G" "$crontabFile")
	if [ $crontabGrp = "root" ]
	then
		echo "[PASS] Group owner of the file ($crontabFile): $crontabGrp" >> ./verification.txt
	else
		echo "[FAILED] Group owner of the file ($crontabFIle): $crontabGrp. Please ensure that the group owner of the file is root instead." >> ./verification.txt
	fi

else
	echo "[FAILED] The crontab file ($crontabFile) does not exist." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if the correct permissions has been set for /etc/cron.XXXX
checkCronHDWMPerm(){
	local cronHDWMType=$1
	local cronHDWMFile="/etc/cron.$cronHDWMType"

	if [ -e "$cronHDWMFile" ]
	then
		local cronHDWMPerm=$(stat -c "%a" "$cronHDWMFile")
		local cronHDWMRegex="^[0-7]00$"
		if [[ $cronHDWMPerm =~ $cronHDWMRegex ]]
		then
			echo "[PASS] Permissions has been set correctly for $cronHDWMFile." >> ./verification.txt
		else
			echo "[FAILED] Ensure that the permissions has been set correctly for $cronHDWMFile." >> ./verification.txt
		fi

		local cronHDWMOwn="$(stat -c "%U" "$cronHDWMFile")"
		if [ $cronHDWMOwn = "root" ]
		then
			echo "[PASS] Owner of the file ($cronHDWMFile): $cronHDWMOwn" >> ./verification.txt
		else
			echo "[FAILED] Owner of the file ($cronHDWMFile): $cronHDWMOwn. Please ensure that the owner of the file is root instead." >> ./verification.txt
		fi

		local cronHDWMGrp="$(stat -c "%G" "$cronHDWMFile")"
		if [ $cronHDWMGrp = "root" ]
		then
			echo "[PASS] Group Owner of the file ($cronHDWMFile): $cronHDWMGrp" >> ./verification.txt
		else
			echo "[FAILED] Group Owner of the file ($cronHDWMFile): $cronHDWMGrp. Please ensure that the group owner of the file is root instead." >> ./verification.txt
		fi
	else
		echo "[FAILED] File ($cronHDWMFile) does not exist." >> ./verification.txt
	fi	
}
echo "" >> ./verification.txt

checkCronHDWMPerm "hourly"
checkCronHDWMPerm "daily"
checkCronHDWMPerm "weekly"
checkCronHDWMPerm "monthly"

#Check if the permissions has been set correctly for /etc/cron.d
cronDFile="/etc/cron.d"
if [ -e "$cronDFile" ]
then
	echo "[PASS] The cron.d file ($cronDFile) exists." >> ./verification.txt
	cronDPerm=$(stat -c "%a" "$cronDFile")
	cronDRegex="^[0-7]00$"
	if [[ $cronDPerm =~ $cronDRegex ]]
	then
		echo "[PASS] Permissions has been set correctly for $cronDFile." >> ./verification.txt
	else
		echo "[FAILED] Ensure that the permissions has been set correctly for $cronDFile." >> ./verification.txt
	fi

	cronDOwn=$(stat -c "%U" "$cronDFile")
	if [ $cronDOwn = "root" ]
	then
		echo "[PASS] Owner of the file ($cronDFile): $cronDOwn" >> ./verification.txt
	else
		echo "[FAILED] Owner of the file ($cronDFile): $cronDOwn. Please ensure that the owner of the file is root instead." >> ./verification.txt
 	fi

	cronDGrp=$(stat -c "%G" "$cronDFile")
	if [ $cronDGrp = "root" ]
	then
		echo "[PASS] Group owner of the file ($cronDFile): $cronDGrp" >> ./verification.txt
	else
		echo "[FAILED] Group owner of the file ($cronDFile): $cronDGrp. Please ensure that the group owner of the file is root instead." >> ./verification.txt
	fi
else
	echo "[FAILED] The cron.d file ($cronDFile) does not exist." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if /etc/at.deny is deleted and that a /etc/at.allow exists and check the permissions of the /etc/at.allow file
atDenyFile="/etc/at.deny"
if [ -e "$atDenyFile" ]
then
	echo "[FAILED] Please ensure that the file $atDenyFile is deleted." >> ./verification.txt
else
	echo "[PASS] $atDenyFile is deleted as recommended." >> ./verification.txt
fi

atAllowFile="/etc/at.allow"
if [ -e "$atAllowFile" ]
then
        atAllowPerm=$(stat -c "%a" "$atAllowFile")
        atAllowRegex="^[0-7]00$"
        if [[ $atAllowPerm =~ $atAllowRegex ]]
        then
            	echo "[PASS] Permissions has been set correctly for $atAllowFile." >> ./verification.txt
        else
            	echo "[FAILED] Ensure that the permissions has been set correctly for $atAllowFile." >> ./verification.txt
        fi

	atAllowOwn=$(stat -c "%U" "$atAllowFile")
        if [ $atAllowOwn = "root" ]
        then
            	echo "[PASS] Owner of the file ($atAllowFile): $atAllowOwn" >> ./verification.txt
        else
            	echo "[FAILED] Owner of the file ($atAllowFile): $atAllowOwn. Please ensure that the owner of the file is root instead." >> ./verification.txt
        fi

	atAllowGrp=$(stat -c "%G" "$atAllowFile")
	if [ $atAllowGrp = "root" ]
	then
		echo "[PASS] Group owner of the file ($atAllowFile): $atAllowGrp" >> ./verification.txt
	else
		echo "[FAILED] Group owner of the file ($atAllowFile): $atAllowGrp. Please ensure that the group owner of the file is root instead." >> ./verification.txt
	fi
else
	echo "[FAILED] Please ensure that a $atAllowFile is created for security purposes." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if /etc/cron.deny is deleted and that a /etc/cron.allow exists and check the permissions of the /etc/cron.allow file
cronDenyFile="/etc/cron.deny"
if [ -e "$cronDenyFile" ]
then
        echo "[FAILED] Please ensure that the file $cronDenyFile is deleted." >> ./verification.txt
else
	echo "[PASS] $cronDenyFile is deleted as recommended." >> ./verification.txt
fi

cronAllowFile="/etc/cron.allow"
if [ -e "$cronAllowFile" ]
then
    	cronAllowPerm=$(stat -c "%a" "$cronAllowFile")
       	cronAllowRegex="^[0-7]00$"
        if [[ $cronAllowPerm =~ $cronAllowRegex ]]
        then
               	echo "[PASS] Permissions has been set correctly for $cronAllowFile." >> ./verification.txt
        else
               	echo "[FAILED] Ensure that the permissions has been set correctly for $cronAllowFile." >> ./verification.txt
       	fi

       	cronAllowOwn=$(stat -c "%U" "$cronAllowFile")
        if [ $cronAllowOwn = "root" ]
        then
                echo "[PASS] Owner of the file ($cronAllowFile): $cronAllowOwn" >> ./verification.txt
        else
               	echo "[FAILED] Owner of the file ($atAllowFile): $cronAllowOwn. Please ensure that the owner of the file is root instead." >> ./verification.txt
    	fi

    	cronAllowGrp=$(stat -c "%G" "$cronAllowFile")
       	if [ $cronAllowGrp = "root" ]
        then
            	echo "[PASS] Group owner of the file ($cronAllowFile): $cronAllowGrp" >> ./verification.txt
        else
            	echo "[FAILED] Group owner of the file ($cronAllowFile): $cronAllowGrp. Please ensure that the group owner of the file is root instead." >> ./verification.txt
        fi
else
    	echo "[FAILED] Please ensure that a $cronAllowFile is created for security purposes." >> ./verification.txt
fi

echo "" >> ./verification.txt

echo "--SSH CONFIGURATIONS--" >> ./verification.txt	
#Set SSH Protocol to 2
chksshprotocol=`grep "^Protocol 2" /etc/ssh/sshd_config`

if [ "$chksshprotocol" == "Protocol 2" ]
then
	echo "[PASS] SSH Protocol has been configured correctly" >> ./verification.txt
else
	echo "[FAILED] SSH Protocol has not been configured correctly." >> ./verification.txt
fi
echo "" >> ./verification.txt

#CHeck if LogLevel has been set to INFO
chksshloglevel=`grep "^LogLevel INFO" /etc/ssh/sshd_config`

if [ "$chksshloglevel" == "LogLevel INFO" ]
then
	echo "[PASS] LogLevel has been set to INFO" >> ./verification.txt
else
	echo "[FAILED] Please ensure that LogLevel has been set to INFO." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check the permissions on /etc/ssh/sshd_config
deterusergroupownership=`/bin/ls -l /etc/ssh/sshd_config | grep "root root" | grep "\-rw-------"`

if [ -n "deterusergroupownership" ] #-n means not null, -z means null
then
	echo "[PASS] The owner and group owner of the /etc/ssh/sshd_config file has been set correctly." >> ./verification.txt
else
	echo "[FAILED] Please ensure that the owner and the group owner of the /etc/ssh/sshd_config file has not been set." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Disbale SSH X11 Forwarding
chkx11forwarding=`grep "^X11Forwarding no" /etc/ssh/sshd_config`

if [ "$chkx11forwarding" == "X11Forwarding no" ]
then
	echo "[PASS] SSH X11 has been disbaled as recommended." >> ./verification.txt
else
	echo "[FAILED] Please ensure that SSH X11 is disabled as recommended." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if SSH MaxAuthTries is 4 or less
maxauthtries=`grep "^MaxAuthTries 4" /etc/ssh/sshd_config`

if [ "$maxauthtries" == "MaxAuthTries 4" ]
then
	echo "[PASS] SSH MaxAuthTries is set to 4 or less." >> ./verification.txt 
else
	echo "[FAILED] SSH MaxAuthTries is not set to 4 or less." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check that SSH IgnoreRhosts is set to yes
ignorerhosts=`grep "^IgnoreRhosts yes" /etc/ssh/sshd_config`

if [ "$ignorerhosts" == "IgnoreRhosts yes" ]
then
	echo "[PASS] SSH IgnoreRhosts is set to yes." >> ./verification.txt
else
	echo "[FAILED] Please ensure that SSH IgnoreRhosts is set to yes" >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if SSH HostbasedAuthentication is set to No
hostbasedauthentication=`grep "^HostbasedAuthentication no" /etc/ssh/sshd_config`

if [ "$hostbasedauthentication" == "HostbasedAuthentication no" ]
then
	echo "[PASS] SSH HostbasedAuthentication is set to No" >> ./verification.txt
else
	echo "[FAILED] Please ensure that SSH HostbasedAuthentication is set to No" >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if SSH Root Login is disabled
chksshrootlogin=`grep "^PermitRootLogin" /etc/ssh/sshd_config`

if [ "$chksshrootlogin" == "PermitRootLogin no" ]
then
	echo "[PASS] SSH Root Login is disabled." >> ./verification.txt
else
	echo "[FAIL] Please ensure that SSH Root Login is disabled" >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if SSH PermitEmptyPasswords
chksshemptypswd=`grep "^PermitEmptyPasswords" /etc/ssh/sshd_config`

if [ "$chksshemptypswd" == "PermitEmptyPasswords no" ]
then
	echo "[PASS] SSH PermitEmptyPasswords is set to no." >> ./verification.txt
else
	echo "[FAIL] Please ensure that SSH PermitEmptyPasswords is set to no" >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if only approved cipher is used in counter mode
chksshcipher=`grep "Ciphers" /etc/ssh/sshd_config`

if [ "$chksshcipher" == "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" ]
then
	echo "[PASS] Only approved cipher is used in counter mode." >> ./verification.txt
else
	echo "[FAILED] Please ensure that only approved cipers has been used in counter mode." >> ./verification.txt 
fi
echo "" >> ./verification.txt

#Ensure that Idle Timeout Interval is set for user login
chksshcai=`grep "^ClientAliveInterval" /etc/ssh/sshd_config`
chksshcacm=`grep "^ClientAliveCountMax" /etc/ssh/sshd_config`

if [ "$chksshcai" == "ClientAliveInterval 300" ]
then
	echo "[PASS] ClientAliveInterval has been set correctly. >> ./verification.txt"
else
	echo "[FAILED] Please ensure that ClientAliveInterval has been set correctly." >> ./verification.txt
fi

if [ "$chksshcacm" == "ClientAliveCountMax 0" ]
then
	echo "[PASS] ClientAliveCountMax has been set correctly." >> ./verification.txt
else
	echo "[FAILED] Please ensure that ClientAliveCountMax has been set correctly" >> ./verification.txt
fi
echo "" >> ./verification.txt

#Limit access via SSH		*NOTE: Manually created users and groups as question was not very specific*
chksshalwusrs=`grep "^AllowUsers" /etc/ssh/sshd_config`
chksshalwgrps=`grep "^AllowGroups" /etc/ssh/sshd_config`
chksshdnyusrs=`grep "^DenyUsers" /etc/ssh/sshd_config`
chksshdnygrps=`grep "^DenyGroups" /etc/ssh/sshd_config`

if [ -z "$chksshalwusrs" -o "$chksshalwusrs" == "AllowUsers[[:space:]]" ]
then
	echo "[FAILED] AllowUsers has not been configured correctly." >> ./verification.txt
else
	echo "[PASS] AllowUsers has been configured correctly." >> ./verification.txt
fi

if [ -z "$chksshalwgrps" -o "$chksshalwgrps" == "AllowGroups[[:space:]]" ]
then
	echo "[FAILED] AllowGroups has not been configured correctly." >> ./verification.txt
else
	echo "[PASS] AllowGroups has been configured correctly." >> ./verification.txt 
fi

if [ -z "$chksshdnyusrs" -o "$chksshdnyusrs" == "DenyUsers[[:space:]]" ]
then
	echo "[FAILED] DenyUsers has not been configured correctly." >> ./verification.txt
else
	echo "[PASS] DenyUsers has been configured correctly." >> ./verification.txt
fi

if [ -z "$chksshdnygrps" -o "$chksshdnygrps" == "DenyGroups[[:space:]]" ]
then
	echo "[FAILED] DenyGroups has not been configured correctly." >> ./verification.txt
else	
	echo "[PASS] DenyGroups has been configured correctly." >> ./verification.txt
fi
echo "" >> ./verification.txt

#10.13 verification
chksshbanner=`grep "Banner" /etc/ssh/sshd_config | awk '{ print $2 }'`

if [ "$chksshbanner" == "/etc/issue.net" -o "$chksshbanner" == "/etc/issue" ]
then
	echo "[PASS] SSH Banner has been set." >> ./verification.txt
else
	echo "[FAILED] SSH Banner has not been set" >> ./verification.txt
fi
echo "" >> ./verification.txt

echo "--PAM CONFIGURATIONS--" >> ./verification.txt
#Check if password hashng algo is SHA-512
checkPassAlgo=$(authconfig --test | grep hashing | grep sha512)
checkPassRegex=".*sha512"
if [[ $checkPassAlgo =~ $checkPassRegex ]]
then
	echo "[PASS] The password hashing algorithm is set to SHA-512 as recommended." >> ./verification.txt
else
	echo "[FAILED] Please ensure that the password hashing algorithm is set to SHA-512 as recommended." >> ./verification.txt
fi 
echo "" >> ./verification.txt

#Check if Password Creattion Requirement Parameters is correct
pampwconf=$(grep pam_pwquality.so /etc/pam.d/system-auth)
correctpampwconf="password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type="
if [[ $pampwconf == $correctpampwconf ]]
then
	echo "[PASS] Recommended settings is already configured for /etc/pam.d/system-auth." >> ./verification.txt
else
	echo "[FAILED] Recommended settings is not configured for /etc/pam.d/system-auth." >> ./verification.txt
fi

minlen=$(grep "minlen" /etc/security/pwquality.conf)
dcredit=$(grep "dcredit" /etc/security/pwquality.conf)
ucredit=$(grep "ucredit" /etc/security/pwquality.conf)
ocredit=$(grep "ocredit" /etc/security/pwquality.conf)
lcredit=$(grep "lcredit" /etc/security/pwquality.conf)
correctminlen="# minlen = 14"
correctdcredit="# dcredit = -1"
correctucredit="# ucredit = -1"
correctocredit="# ocredit = -1"
correctlcredit="# lcredit = -1"

if [[ $minlen == $correctminlen && $dcredit == $correctdcredit && $ucredit == $correctucredit && $ocredit == $correctocredit && $lcredit == $correctlcredit ]]
then
	echo "[PASS] Recommended settings is already configured for /etc/security/pwquality.conf." >> ./verification.txt
else
	echo "[FAILED] Recommended settings is not configured for /etc/security/pwquality.conf." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if Lockout for Failed Password Attempts is set
faillockpassword=$(grep "pam_faillock" /etc/pam.d/password-auth)
faillocksystem=$(grep "pam_faillock" /etc/pam.d/system-auth)

read -d '' correctpamauth << "BLOCK" 
auth        required      pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth        [default=die] pam_faillock.so authfail audit deny=5
auth        sufficient    pam_faillock.so authsucc audit deny=5
account     required      pam_faillock.so
BLOCK

if [[ $faillocksystem == "$correctpamauth" && $faillockpassword == "$correctpamauth" ]]
then
	echo "[PASS] Lockout for Failed Password Attempts is set." >> ./verification.txt
else
	echo "[FAILED] Lockout for Failed Password Attempts is not set." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if password resuse has been limited
pamlimitpw=$(grep "remember" /etc/pam.d/system-auth)
if [[ $pamlimitpw == *"remember=5"* ]]
then 
echo "[PASS] Password resuse has been limited." >> ./verification.txt
else
echo "[FAILED] Password resuse has not been limited." >> ./verification.txt
fi
echo "" >> ./verification.txt

#Check if root Login to System Console is restricted
systemConsole="/etc/securetty"
systemConsoleCounter=0
while read -r line; do
	if [ -n "$line" ]
	then
		[[ "$line" =~ ^#.*$ ]] && continue
		if [ "$line" == "vc/1" ] || [ "$line" == "tty1" ]
		then
			systemConsoleCounter=$((systemConsoleCounter+1))
		else
			systemConsoleCounter=$((systemConsoleCounter+1))
		fi
	fi
done < "$systemConsole"

if [ $systemConsoleCounter != 2 ]
then
	echo "[PASS] Root Login to System Console is restricted" >> ./verification.txt
else
	echo "[FAILED Root Login to System Console is not restricted" >> ./verification.txt
fi
echo "" >> ./verification.txt

#Access to the su Command is restricted
pamsu=$(grep pam_wheel.so /etc/pam.d/su | grep required)
if [[ $pamsu =~ ^#auth.*required ]]
then
	echo "[PASS] The/etc/pam.d/su is configured correctly for restricting the execution of the su command." >> ./verification.txt
else
	echo "[FAILED] Please ensure that the /etc/pam.d/su is configured correctly for restricting the execution of the su command." >> ./verification.txt
fi

pamwheel=$(grep wheel /etc/group)
if [[ $pamwheel =~ ^wheel.*root ]]
then
	echo "[PASS] The/etc/group is configured correctly for restricting the execution of the su command." >> ./verification.txt
else
	echo "[FAILED] Please ensure that the /etc/group is configured correctly for restricting the execution of the su command." >> ./verification.txt
fi

echo "Please refer to the verification file created on your desktop for the full analysis report."
