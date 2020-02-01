#!/usr/bin/perl

use Env qw(USER);
use IO::Socket::INET;

my ($ip,$mac);
open (my $ph,"/sbin/ifconfig -a|");
while (<$ph>)
{
  if (m/inet (129.62.\d+\.\d+)/)
  {
    $ip=$1; 
  }
  if ($ip && m/ether (.*)$/)
  {
    $mac=$1;
    last;
  }
}

open (my $ph,"/usr/sbin/scutil --get LocalHostName|");
my $host = <$ph>;
chomp @host;

# print "ip=$ip\nmac=$mac\nuser=$USER\nhost=$host\n";
&SendLLog( {'ipaddress' => $ip,
            'hardware' => $mac,
            'machinename' => $host,
            'bearid' => $USER,
            'tag' => 'MAC_OSX_PERL',
            'realm' => 'ELCS_LAB'} );

print "linkinlog: caught " . $USER . " into " . $host . " from PID " . getppid . "\n";

sub SendLLog {

  my ( $hashref ) = @_;

  my ($tag,$bid,$rlm,$mac,$ip,$pc);

  $tag = $hashref->{'tag'}         || "MAC_OSX";
  $bid = $hashref->{'bearid'}      || return -1;
  $rlm = $hashref->{'realm'}       || "PERL_CLIENT";
  $mac = $hashref->{'hardware'}    || "UNAVAILABLE";
  $ip  = $hashref->{'ipaddress'}   || return -1;
  $pc  = $hashref->{'machinename'} || "UNAVAILABLE";

  my $server="linkinlog.server";
  my $servport=9876;

  my $sock = IO::Socket::INET->new(
    Proto => 'udp',
    PeerAddr => "$server:$servport"
  );

  my %packet_type =
  (  'packet_Unknown'    => 0,
     'packet_LogIn'      => 1,
     'packet_LogOut'     => 2,
     'packet_IdleLogOut' => 3
  );

  # typedef struct
  # {
  #     char mMagic[2]; /* this must be 'LL' */
  #     char mType;
  #     char mAttempt;
  #     char mTag[12];
  #     char mBearID[32];
  #     char mRealm[32];
  #     char mHardware[24];
  #     char mIPAddress[24];
  #     char mMachineName[32];
  # } LinkinLogRec, *LinkinLogPtr;

  my $packet_template  = "C";        # mMagic[0]
     $packet_template .= "C";        # mMagic[1]
     $packet_template .= "C";        # mType
     $packet_template .= "C";        # mAttempt
     $packet_template .= "a12";      # mTag
     $packet_template .= "a32";      # mBearID
     $packet_template .= "a32";      # mRealm
     $packet_template .= "a24";      # mHardware
     $packet_template .= "a24";      # mIPAddress
     $packet_template .= "a32";      # mMachineName

  my $data = pack($packet_template, 
                   ord('L'), ord('L'), $packet_type{'packet_LogIn'}, 
                   1, $tag, $bid, $rlm, $mac, $ip, $pc);

  $sock->send($data);
  return 1;
}
