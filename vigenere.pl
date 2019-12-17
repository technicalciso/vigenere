#!/usr/bin/perl
############################################################################
#vigenere.pl  (Vigenère Cipher)                                            #
#version 1.1  (Dec 2019)                                                   #
# by Ely Pinto technicalciso.com                                           #
############################################################################

############################################################################
#general assumptions                                                       #
# english language                                                         #
# non-alpha characters are ignored                                         #
# all letters are transformed to uppercase                                 #
# ciphertext must be long enough to guess                                  #
#                                                                          #
#uses the Kasiski method                                                   #
#code is a bit sloppy, live with it for now                                #
############################################################################

############################################################################
#preliminary                                                               #
############################################################################
use strict;
use warnings;
use Getopt::Long;

my $MAXKEYLENGTHS=5;	#specify how many keylengths to try

############################################################################
#options                                                                   #
############################################################################
my $USAGE = <<USAGE;

Usage: $0 [OPTIONS]  
Encrypt or decrypt text using the Vigenère Cipher

Options:
        --encrypt               Text to encrypt 
        --decrypt               Text to decrypt
        --key             	Encryption key
        --guess                 Attempt to guess the key
        --help                  Display this help

USAGE

@ARGV or die $USAGE;
my $opts = {};
{
	local $SIG{__WARN__} = sub { print "@_\n"; exit 6 };
        GetOptions(
                'help'          => \$opts->{'help'},
                'guess'         => \$opts->{'guess'},
                'encrypt=s'       => \$opts->{'encrypt'},
                'decrypt=s'       => \$opts->{'decrypt'},
                'key=s'         => \$opts->{'key'},
        );

        $opts->{'help'} && do { print $USAGE; exit };
        $opts->{'key'}  || die "Please specify key to use\n" unless $opts->{'guess'};
        $opts->{'encrypt'} || $opts->{'decrypt'} || die "Please specify encryption or decryption\n";
	die "Please specify encryption or decryption\n" if ($opts->{'encrypt'} && $opts->{'decrypt'});
	die "Guessing only works with decryption\n" if ($opts->{'guess'} && $opts->{'encrypt'});
	die "Why guess if you already have a key?\n" if ($opts->{'guess'} && $opts->{'key'});
}

my ($decode, $text, $key);

if ($opts->{'encrypt'}) {
	$decode=1; 
	$text=uc($opts->{'encrypt'});
} else {
	$decode=-1; 
	$text=uc($opts->{'decrypt'});
}

#sorry, no numbers or spaces
$text=~s/[^A-Z]//g;


sub myguess{
#this is the hard part
	
	my %englishLetterFreq = (
	#based on Wikipedia 
		'E'=>12.70, 'L'=>4.03, 'Y'=>1.97, 'P'=>1.93, 'T'=>9.06, 'A'=>8.17, 'O'=>7.51, 'I'=>6.97, 'N'=>6.75, 'S'=>6.33, 'H'=>6.09, 'R'=>5.99, 'D'=>4.25, 'C'=>2.78, 'U'=>2.76, 'M'=>2.41, 'W'=>2.36, 'F'=>2.23, 'G'=>2.02, 'B'=>1.29, 'V'=>0.98, 'K'=>0.77, 'J'=>0.15, 'X'=>0.15, 'Q'=>0.10, 'Z'=>0.07);

	my ($text) = (@_);
	my ($seqtext,$pos,$i);
	my @spacing;
	my @factors;
	my @sortedfactors;
	$seqtext=$text;

	#find repeating sequences and how far apart they are
	$pos = 0;                       
	while ($seqtext =~ /(...).*\1/) {  
		#adopted from Klaus Pommerening
  		$i = index($seqtext, $1);        
  		$pos += $i;                    
  		$i++;                         
  		$seqtext = substr($seqtext, $i);    
  		$pos++;                       
  		$i = index($seqtext, $1);        
  		push @spacing, $i+1;
  	}
	
	#find the top factors of the spacings
	foreach my $j (@spacing) {
		push @factors, (grep { $j % $_ == 0 }(2 .. $j));
	}
	
	my %freq;
	$freq{$_}++ for @factors;

	foreach (sort { $freq{$b} <=> $freq{$a} } keys %freq) {
  		push @sortedfactors, "$_";
	}
	
	splice @sortedfactors, $MAXKEYLENGTHS;
	#@sortedfactors now has our top $MAX_KEYLENGTHS most likely keylengths
 
	foreach my $keylen (@sortedfactors) {
		my $keyguess;
		for (my $i=0; $i<$keylen; $i++) {
			my $mykey;
			my %chivalues;
			my $bestchi; 
			my $bestguess; 
			for (my $j=0; $j<length($text); $j+=$keylen) {
				$mykey.=substr($text,($j+$i)%length($text),1);
			}
			
			foreach my $subkey ("A".."Z") {
				my $chi=0;
				my $decrypted=mycrypt($mykey,$subkey,$decode);
				my $length = length($decrypted);
				foreach my $char ("A".."Z") {
					my $count=0;
					my $expected = $length*$englishLetterFreq{$char}/100;
					++$count while $decrypted =~ /\Q$char/g;
					$chivalues{$subkey}+=($count - $expected)**2/$expected unless (!$count);
				}
			}
			foreach my $sk (keys %chivalues) {
			#not the best way to do this
			#1. does not account for two or more values that are the same
			#2. only tests the best choice; should several top choices especially if they are close
				if (!$bestchi || $chivalues{$sk} < $bestchi) {
         				$bestchi = $chivalues{$sk};
					$bestguess = $sk;
				}
             		} 				
			$keyguess.=$bestguess;
		}
		#printing from the subroutine is ugly, need to fix
		#should return an error if no keys were found
		print "keylength $keylen: $keyguess \n";
	}
}

sub mycrypt {
	my ($text,$key,$decode) = (@_);
	my $keylen=length($key);
	my $newtext;
	my %values_numbers; #find numbers with letters
	@values_numbers {"A".."Z"} = (0..25);
	my %values_letters = reverse %values_numbers; #find letters with numbers

	for (my $i=0; $i<length($text); $i++) {
		$newtext.=$values_letters{($values_numbers{substr($text,$i,1)}+$decode*$values_numbers{substr($key,($i%$keylen),1)})%26};
	}
	return $newtext;
}

if ($opts->{'guess'}) {
	print "Most likely keys...\n";
	myguess($text);
} else {
	$key=uc($opts->{'key'});
	print mycrypt ($text,$key,$decode);
}

print "\n";
exit;
