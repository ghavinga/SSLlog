#!/usr/bin/perl -w 
strict;
# sonicwallLogReported.pl
# Version 1.00, January 2011, G. Havinga, UEBV
# Latest change to add new value c= in new log format since Sonicwall
# upgraded
# This script swallows a Sonicwall SSL gateway syslog file and attempts to summarise
# the most important statistics
#
# What information do I need;
# user - name
# user - login time (page access) -
#    There is one login message type: msg="User log in successful" m=1 but is also used for failures!
#    There are two logout message types: msg="User auto logged out" and msg="User logged out" m=2
# user - what has been accessed
# user - failed login
#    There is one message type: msg="User log in failed" also for m=1
# http/https access for m=18
# CRL update for m=35
# Various HTTP error messages for m=28
# my ($user, $date, $url);

sub usage {
    	if ( $#ARGV lt 1 ) {
     	  	print "usage: $0 log_file log_type [user name]\n";
       		print "  log_type = 0 for summary\n"; 
     	  	print "  log_type = 1 for log in list per user\n"; 
       		print "  log_type = 1f for failed log-ins only per user\n"; 
       		print "  log_type = 2 for log out list per user and duration of session\n"; 
       		print "  log_type = 18 for access list per user (accepts optional user name as 3rd parameter)\n"; 
       		print "  log_type = 18e for access list per user for netextender sessions\n"; 
       		print "  log_type = 18r for access list per user for RDP sessions\n"; 
       		print "  log_type = 28 for access list errors per user\n"; 
      	 	print "  log_type = 35 CRL update experimental\n"; 
       		print "  log_type = priv for total access list per privileged host (needs privIPs file)\n";
       		print "  log_type = privsum for summary access list per privileged host (needs privIPs file)\n";
       		print "  log_type = main for maintenance messages (type m=0)\n";
		print "version $version\n";
	exit }
} 

sub init {
	# Initialise hashes here
	$version = "1.00";
	
}

sub readLogFile {
	# Obsolete, starts a shell and is a potential security risk (replaced by Peters
	# version)
	$logf=$ARGV[0]; 
	@logf=( `cat $logf` ); # read log f into an array
}

sub readPrivIPs {
	$privIPs="privIPs";
	open (PFH, $privIPs) or die "Privileged hosts file $privIPs not found dummy\n\n";
	@privIPs = <PFH>;
	foreach $pIps (@privIPs){
    		# chomp;                  # remove newline
    		$pIps =~ s/\s+$//;               # remove trailing white
		# print $pIps;
	}
}
 
sub readLogFilePeter {
	open (FH,$ARGV[0]) or die "Log file $ARGV[0] not accessible, giving up if you don't want to play.\n\n";
	@logf = <FH>; 
} 

sub readmFlag {
    # m is the log type field used by the Sonicwall SSL gateway
#    if ($ARGV[1] eq 1 || $ARGV[1] eq 18) {
    if ($ARGV[1] eq 1 or "1f" or 2 or 18 or 28 or "18e" or "18h") {
        $mFlag = $ARGV[1];
    }
    else {
        $mFlag = 0;
    }
}

sub readUserFlag {
    # Hidden flag to restrict output to one user only, only used where m=18
    $userFlag = $ARGV[2];
} 

sub normalize {
    # Trying to arrange a case insensitive sort for the user names
    my $in = $_[0];
    # $in =~ tr/Ññ/Nn/;
    $in =~ tr/'//d; # d for delete
    return lc($in);
}


sub eventTypes {
    %mTypes = (	'0' => 'Maintenance messages', 
    		'1' => 'Login - successful and failures',
               '2' => 'Logout',
               '3' => 'Unknown',
               '4' => 'Unknown',
               '5' => 'Unknown',
               '6' => 'Logout',
               '7' => 'Unknown',
               '8' => 'Unknown',
               '9' => 'Unknown',
               '10' => 'Logout',
               '11' => 'Unknown',
               '12' => 'Unknown',
               '13' => 'Unknown',
               '14' => 'Logout',
               '15' => 'Unknown',
               '16' => 'Unknown',
               '17' => 'Unknown',
               '18' => 'HTTP/HTTPS pages accessed',
               '19' => 'Unknown',
               '20' => 'Unknown',
               '21' => 'Unknown',
               '22' => 'Unknown',
               '23' => 'Unknown',
               '24' => 'Unknown',
               '25' => 'Unknown',
               '26' => 'Unknown',
               '27' => 'Unknown',
               '28' => 'Various HTTP/HTTPS error messages',
               '29' => 'Unknown',
               '30' => 'Unknown',
               '31' => 'Unknown',
               '32' => 'Unknown',
               '33' => 'Unknown',
               '34' => 'Unknown',
               '35' => 'CRL update');
}

sub foundUsers {
    # Create array containing all users, sort in (human) alfabetical order.
    # This array is used to generate list of log events per user 
    $prev = 'null'; # remove duplicates
    @alpha = sort { normalize($a) cmp normalize($b) } @usrArray;
    @usrArray = grep($_ ne $prev && ($prev = $_), @alpha); 
}


sub printFoundUsers {
    	print "Found the following users for this log file:\n";
	$cnt=0;
    	foreach $usrElement ( @usrArray ) { 
            	printf "%-20s","$usrElement ";
		$cnt++;
	 	if ($cnt % 5 eq 0) {
			print "\n";
	     		}
    	}
}

sub printFoundPrivIPs {
	#print "Found the following privileged IP hosts in the log file:\n";
	print "Access list report for each defined privileged host (hosts defined in privIPs file)\n";
	foreach $privHost ( @privIPs ) {
		$count = 0;
		print "---- $privHost ----\n";
		# Scan the logfile (unfortunately once for each host .....)
    		# Scanning through log array and building data structures
    		# Depending on the kind of report required (logtype) we build a hash with user name (from usr field)
    		# as index. The interesting log fields (currently time, source and message) are stored in a two
    		# dimensional array (3 fields per log entry) and attached to the hash fo each user.
    		foreach $line ( @logf ) {
          		$line =~ m/time=(.*) vp_time=(.*) fw=(.*) pri=(.*) m=(.*) src=(.*) dst=(.*) user=(.*) usr=(.*) msg=(.*) agent=(.*)/;
          		$time  =  $1;
          		$vp_time = $2;
          		$fw  =    $3;
          		$pri =    $4;
          		$m  =     $5;
          		$src =    $6;
          		$dst =    $7;
          		$user =   $8;
          		$usr =    $9;
          		$msg =   $10;
          		$remainder = $11;
        		$count++;
			if ( $dst eq $privHost ) {
				# print $line;
				if ($count == 1) {
					print "No log access for this host in this log file\n";
				}
				else {
					# print "$user $time $src $dst $msg\n";
					printf "%-15s","$user";
					printf "%-22s","$time";
					printf "%-17s","$src";
					printf "%-17s","$dst";
					printf "%-40s","$msg";
					print "\n";
				}
			}

		}	
	}
}

sub printSummaryFoundPrivIPs {
	#print "Found the following privileged IP hosts in the log file:\n";
	print "Summary access list report for each defined privileged host (hosts defined in privIPs file).\n";
	print "WARNING: summary is generated from user name and originating IP address (when either is different).\n";
	foreach $privHost ( @privIPs ) {
		$count = 0;
		print "---- $privHost ----\n";
		# Scan the logfile (unfortunately once for each host .....)
    		# Scanning through log array and building data structures
    		# Depending on the kind of report required (logtype) we build a hash with user name (from usr field)
    		# as index. The interesting log fields (currently time, source and message) are stored in a two
    		# dimensional array (3 fields per log entry) and attached to the hash fo each user.
		$prev_src = "";
    		foreach $line ( @logf ) {
          		$line =~ m/time=(.*) vp_time=(.*) fw=(.*) pri=(.*) m=(.*) src=(.*) dst=(.*) user=(.*) usr=(.*) msg=(.*) agent=(.*)/;
          		$time  =  $1;
          		$vp_time = $2;
          		$fw  =    $3;
          		$pri =    $4;
          		$m  =     $5;
          		$src =    $6;
          		$dst =    $7;
          		$user =   $8;
          		$usr =    $9;
          		$msg =   $10;
          		$remainder = $11;
        		$count++;
			if ( $dst eq $privHost ) {
				# print $line;
				if ($count == 1) {
					print "No log access for this host in this log file\n";
				}
				else {
					if ( $src ne $prev_src ) {  
						# print "$user $time $src $dst $msg\n";
						printf "%-15s","$user";
						printf "%-22s","$time";
						printf "%-17s","$src";
						printf "%-17s","$dst";
						printf "%-40s","$msg";
						print "\n";
						$prev_src = $src;
					}
				}
			}

		}	
	}
}

sub printLogEntryTypes {
	print "$0, version $version\n\n";
   	# $prev = 'null'; # remove duplicates
   	$prev = ''; # remove duplicates
   	# @alpha = sort { normalize($a) cmp normalize($b) } @mArray;
   	@alpha = sort { $a <=> $b } @mArray;
	# print "@mArray\n\n";
   	# @mArray = grep($_ ne $prev && ($prev = $_), @alpha);
   	@mArray = grep($_ ne $prev && ($prev = $_) ne '', @alpha);
	# print "@mArray";
   	print "Found the following log entry types (value of m):\n"; 
   	foreach $mElement ( @mArray ) { 
        	print "$mElement = $mTypes{$mElement}\n";
  }
}
 
sub printM0PerUser {
    print "Maintenance (m=0) messages for each user:\n";
    foreach $m0Element ( sort keys %m0Hash ) { 
        $len =  scalar( @{$m0Hash{$m0Element}} );
        $cnt=0;
        print "---------------------------------------------------------------------------------\n";
	printf "%-17s","$m0Element";
        printf "%-5s",$len/4;
	printf "%-18s","Source IP"; 
	printf "%-22s","Dest IP"; 
	print "\n";
        	foreach $m0List ( @{$m0Hash{$m0Element}}) {
        	$cnt++;
	 	printf "%-18s","$m0List ";
	 	if ($cnt % 4 eq 0) {
			print "\n";
	     		}
		}
	}
}

sub printM1PerUser {
    foreach $m1Element ( sort keys %m1Hash ) { 
        $len =  scalar( @{$m1Hash{$m1Element}} );
        $cnt=0;
        print "---------------------------------------------------------------------------------\n";
	printf "%-17s","$m1Element";
        printf "%-5s",$len/4;
	printf "%-18s","Source IP"; 
	printf "%-22s","Dest IP"; 
	print "\n";
        	foreach $m1List ( @{$m1Hash{$m1Element}}) {
        	$cnt++;
	 	printf "%-18s","$m1List ";
	 	if ($cnt % 4 eq 0) {
			print "\n";
	     		}
		}
	}
}

sub printM1fPerUser {
	# Print login entries with "User log in failed" in message part
    foreach $m1fElement ( sort keys %m1fHash ) { 
        $len =  scalar( @{$m1fHash{$m1fElement}} );
        $cnt=0;
        print "---------------------------------------------------------------------------------\n";
	printf "%-17s","$m1fElement";
        printf "%-5s",$len/4;
	printf "%-18s","Source IP"; 
	printf "%-22s","Dest IP"; 
	print "\n";
        	foreach $m1fList ( @{$m1fHash{$m1fElement}}) {
        	$cnt++;
	 	# print "$m1fList   ";
	 	printf "%-18s","$m1fList ";
	 	if ($cnt % 4 eq 0) {
			print "\n";
	     		}
		}
	}
}

sub printM2PerUser {
    foreach $m2Element ( sort keys %m2Hash ) { 
        $len =  scalar( @{$m2Hash{$m2Element}} );
        $cnt=0;
        print "------------------------------------------------------------\n";
        print "$m2Element =>", $len/5 ,"\n";
        	foreach $m2List ( @{$m2Hash{$m2Element}}) {
        	$cnt++;
	 	printf "%-22s","$m2List";
	 	if ($cnt % 5 eq 0) {
			print "\n";
	     		}
		}
	}
}


sub printM18PerUser {
    foreach $m18Element ( sort keys %m18Hash ) { 
        $len =  scalar( @{$m18Hash{$m18Element}} );
        # print "$len - ";
        if ($len eq 0) {
           print "$m18Element => NO PAGES ACCESSED\n";
        }
        else {
            $cnt=0;
            print "$m18Element =>", $len/4 ,"\n";
            foreach $m18List ( @{$m18Hash{$m18Element}}) {
            $cnt++;
	    print "$m18List ";
	     if ($cnt % 4 eq 0) {
	     	print "\n";
	        }
	   }
       }
   }
}


sub printM18PerUserOneUserOnly {
	$m18Element = $userFlag; 
        $len =  scalar( @{$m18Hash{$m18Element}} );
        if ($len == 0) {
           print "$m18Element => NO PAGES ACCESSED or NOT FOUND IN LOG FILE\n";
        }
        else {
            $cnt=0;
            print "$m18Element =>", $len/4 ,"\n";
            foreach $m18List ( @{$m18Hash{$m18Element}}) {
            $cnt++;
	    print "$m18List ";
	     if ($cnt % 4 eq 0) {
	     	print "\n";
	        }
	   }
       }
}

sub printM18NetExtender {
	foreach $m18ElementNetExtender ( keys %m18HashNetExtender ){
                $len = scalar( @{$m18HashNetExtender{$m18ElementNetExtender}} );
                $cnt=0;
		print "$m18ElementNetExtender ====>", $len/4," NetExtender access record(s) found.\n"; 
			foreach $m18ListNetextender ( @{$m18HashNetExtender{$m18ElementNetExtender}}) {
				$cnt++;	
				# print "$m18ListNetextender   ";
				printf "%-18s","$m18ListNetextender ";
             			if ($cnt % 4 eq 0) {
                			print "\n";
                			}
			}
		}
}

sub printM18RDP {
	foreach $m18ElementRDP ( keys %m18HashRDP ){
                $len = scalar( @{$m18HashRDP{$m18ElementRDP}} );
                $cnt=0;
		print "$m18ElementRDP ====> ", $len/4," remote desktop access record(s) found.\n"; 
			foreach $m18ListRDP ( @{$m18HashRDP{$m18ElementRDP}}) {
				$cnt++;	
				# print "$m18ListRDP   ";
				printf "%-18s","$m18ListRDP ";
             			if ($cnt % 4 eq 0) {
                			print "\n";
                			}
			}
		}
}

sub printM28PerUser {
    foreach $m28Element ( sort keys %m28Hash ) { 
        $len =  scalar( @{$m28Hash{$m28Element}} );
        # print "$len - ";
        if ($len eq 0) {
           print "$m28Element => NO PAGES ACCESSED\n";
        }
        else {
            $cnt=0;
            print "$m28Element =>", $len/3 ,"\n";
            foreach $m28List ( @{$m28Hash{$m28Element}}) {
            $cnt++;
	    # print "$m28List ";
	    printf "%-20s","$m28List ";
	     if ($cnt % 3 eq 0) {
	     	print "\n";
	        }
	   }
       }
   }
}

sub printM35 {
	foreach $m35Element (sort keys %m35Hash) {
		$len = scalar( @{$m35Hash{$m35Element}} );
		if ($len eq 0) {
			print "$m35Element => NO CRL UPDATES\n";
		}
		else {
			$cnt = 0;
			print "$m35Element =>";
			foreach $m35List ( @{$m35Hash{$m35Element}}) {
				$cnt++;
				printf "%-10s","$m35List  ";
				if ($cnt % 4 eq 0) {
					print "\n";
				}
			}
		}
	}
}


sub processLogEntries {
    # Scanning through log array and building data structures
    # Depending on the kind of report required (logtype) we build a hash with user name (from usr field)
    # as index. The interesting log fields (currently time, source and message) are stored in a two
    # dimensional array (3 fields per log entry) and attached to the hash fo each user.
    foreach $line ( @logf ) {
          # $line =~ m/time=(.*) vp_time=(.*) fw=(.*) pri=(.*) m=(.*) src=(.*) dst=(.*) user=(.*) usr=(.*) msg=(.*) agent=(.*)/;
          $line =~ m/time=(.*) vp_time=(.*) fw=(.*) pri=(.*) m=(.*) c=(.*) src=(.*) dst=(.*) user=(.*) usr=(.*) msg=(.*) agent=(.*)/;
          $time  =  $1;
          $vp_time = $2;
          $fw  =    $3;
          $pri =    $4;
          $m  =     $5;
            push @mArray, $m;
	  $cnew =   $6;
          $src =    $7;
          $dst =    $8;
          $user =   $9;
          $usr =    $10;
            $usr =~ tr/"//d;
            push @usrArray, $usr;
          $msg =   $11;
          $remainder = $12;
          
        $count++;
	if ($count eq 1) {
		$firstLogTime = $time;
		}
        # print "$line\n";
	if ($m eq 0) {
		# Maintenance messages
		if ($mFlag eq "main") { 
        		push (@{$m0Hash{$usr}},  $time, $src, $dst, $msg);
			# print "$m ";
			}
        } 
        if ($m eq 1) {
            #print "$count - $time - $m - $src - $usr - $msg\n";
            # Log in log entries (successful and failed).
            # Create a hash with user name as index, attach relevant log entries as array to each user hash
            if ($mFlag eq 1) {
               push (@{$m1Hash{$usr}},  $time, $src, $dst, $msg);
               } else {
		if ($mFlag eq "1f" && $msg =~ (/^"User login failed"*/)) {
			push (@{$m1fHash{$usr}}, $time, $src, $dst, $msg);
			}
		}
            }
        if ($m eq 2) {
            if ($mFlag eq 2) {
		$msg =~ m/duration=(.*)/;
                @loginDuration = gmtime($1) ;
                $loginDurationString = 	" - ".$loginDuration[7]."d ".
					$loginDuration[2].":".
					$loginDuration[1].":".
					$loginDuration[0]; 
               	push (@{$m2Hash{$usr}},  $time, $src, $dst, $msg, $loginDurationString);
               }
            #print "$count - $time - $m - $src - $usr - $msg\n";
            }
        if ($m eq 18) {
            # print "$count - $time - $m - $src - $usr - $msg\n";
            if ($mFlag eq 18) {
                push (@{$m18Hash{$usr}},  $time, $src, $dst, $msg);
                }
	    if ($mFlag eq "18e") {
                $msg =~ m/proto=(.*)/;
                $protocol = $1;
		if ($protocol eq "NetExtender") {
                	push (@{$m18HashNetExtender{$usr}},  $time, $src, $dst, $msg);
                        # print "$usr - $src - $dst - $protocol\n";
			}
                }
	    if ($mFlag eq "18r") {
                $msg =~ m/proto=(.*)/;
                $protocol = $1;
                # print "$protocol\n";
		if ($protocol =~ /RDP/) {
                	push (@{$m18HashRDP{$usr}},  $time, $src, $dst, $msg);
                        #print "$usr - $src - $dst - $protocol\n";
			}
                }
            }
        if ($m eq 28) {
            # print "$count - $time - $m - $src - $usr - $msg\n";
            if ($mFlag eq 28) {
                push (@{$m28Hash{$usr}},  $time, $src, $msg);
                }
            }
        if ($m eq 35 && $mFlag eq "35") {
            #print "$count - $time - $m - $src - $usr - $msg\n";
            push (@{$m35Hash{$time}},  $m, $src, $usr, $msg);
            }
        }
	$totalNumberLogEntries = $count;
	$lastLogTime = $time; # Does this work? It is outside the loop, need to carefully check
}

sub printLogStats {
	print "Total number of log entries processed $totalNumberLogEntries\n";
	print "Time first log entry $firstLogTime\n";
	print "Time last log entry  $lastLogTime\n\n";
}


# Main program

init ();
usage ();
eventTypes ();
#readLogFile ();
readLogFilePeter ();
readmFlag ();
readUserFlag ();
processLogEntries ();
foundUsers ();
printLogEntryTypes ();
print "\n\n";
printLogStats ();
printFoundUsers ();
print "\n\n";
if ($mFlag eq "main") { 
   	printM0PerUser ();
   	}
if ($mFlag eq 1) { 
   	printM1PerUser ();
   	}
if ($mFlag eq "1f") {
	printM1fPerUser ();
	}
if ($mFlag eq 2) { 
	printM2PerUser (); 
	}
if ($mFlag eq 18) {
   	if ($userFlag eq "") {
      		printM18PerUser ();
   		}	
   	else {
   		printM18PerUserOneUserOnly ();
   		}
   }
if ($mFlag eq "18e") {
	printM18NetExtender ();
}

if ($mFlag eq "18r") {
	printM18RDP ();
}

if ($mFlag eq 28) {
   printM28PerUser ();
}

if ($mFlag eq 35) {
   printM35 ();
}

if ($mFlag eq 99) {
	# Extended statistics
	processExtendedStats ();
}

if ($mFlag eq "priv") {
	readPrivIPs ;
	printFoundPrivIPs ;
}
if ($mFlag eq "privsum") {
	readPrivIPs ;
	printSummaryFoundPrivIPs ;
}
