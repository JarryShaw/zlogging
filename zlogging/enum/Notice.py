# -*- coding: utf-8 -*-
"""Namespace: ``Notice``."""

from zlogging._compat import enum


@enum.unique
class Action(enum.IntFlag):
    """These are values representing actions that can be taken with notices.

    c.f. `base/frameworks/notice/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/notice/main.zeek.html#type-Notice::Action>`__

    """

    _ignore_ = 'Action _'
    Action = vars()

    #: Indicates that there is no action to be taken.
    Action['ACTION_NONE'] = enum.auto()

    #: Indicates that the notice should be sent to the notice
    #: logging stream.
    Action['ACTION_LOG'] = enum.auto()

    #: Indicates that the notice should be sent to the email
    #: address(es) configured in the Notice::mail\_dest
    #: variable.
    Action['ACTION_EMAIL'] = enum.auto()

    #: Indicates that the notice should be alarmed.  A readable
    #: ASCII version of the alarm log is emailed in bulk to the
    #: address(es) configured in Notice::mail\_dest.
    Action['ACTION_ALARM'] = enum.auto()

    #: (present if base/frameworks/notice/actions/email\_admin.zeek is loaded)
    #: Indicate that the generated email should be addressed to the
    #: appropriate email addresses as found by the
    #: Site::get\_emails function based on the relevant
    #: address or addresses indicated in the notice.
    Action['ACTION_EMAIL_ADMIN'] = enum.auto()

    #: (present if base/frameworks/notice/actions/page.zeek is loaded)
    #: Indicates that the notice should be sent to the pager email
    #: address configured in the Notice::mail\_page\_dest
    #: variable.
    Action['ACTION_PAGE'] = enum.auto()

    #: (present if base/frameworks/notice/actions/add-geodata.zeek is loaded)
    #: Indicates that the notice should have geodata added for the
    #: “remote” host.  Site::local\_nets must be defined
    #: in order for this to work.
    Action['ACTION_ADD_GEODATA'] = enum.auto()

    #: (present if policy/frameworks/notice/actions/drop.zeek is loaded)
    #: Drops the address via NetControl::drop\_address\_catch\_release.
    Action['ACTION_DROP'] = enum.auto()


@enum.unique
class Type(enum.IntFlag):
    """Scripts creating new notices need to redef this enum to add their
    own specific notice types which would then get used when they call
    the NOTICE function.  The convention is to give a general
    category along with the specific notice separating words with
    underscores and using leading capitals on each word except for
    abbreviations which are kept in all capitals. For example,
    SSH::Password\_Guessing is for hosts that have crossed a threshold of
    failed SSH logins.

    c.f. `base/frameworks/notice/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/notice/main.zeek.html#type-Notice::Type>`__

    """

    _ignore_ = 'Type _'
    Type = vars()

    #: Notice reporting a count of how often a notice occurred.
    Type['Tally'] = enum.auto()

    #: Weird::Activity
    #: (present if base/frameworks/notice/weird.zeek is loaded)
    #: Generic unusual but notice-worthy weird activity.
    Type['Weird__Activity'] = enum.auto()

    #: Signatures::Sensitive_Signature
    #: (present if base/frameworks/signatures/main.zeek is loaded)
    #: Generic notice type for notice-worthy signature matches.
    Type['Signatures__Sensitive_Signature'] = enum.auto()

    #: Signatures::Multiple_Signatures
    #: (present if base/frameworks/signatures/main.zeek is loaded)
    #: Host has triggered many signatures on the same host.  The
    #: number of signatures is defined by the
    #: Signatures::vert\_scan\_thresholds variable.
    Type['Signatures__Multiple_Signatures'] = enum.auto()

    #: Signatures::Multiple_Sig_Responders
    #: (present if base/frameworks/signatures/main.zeek is loaded)
    #: Host has triggered the same signature on multiple hosts as
    #: defined by the Signatures::horiz\_scan\_thresholds
    #: variable.
    Type['Signatures__Multiple_Sig_Responders'] = enum.auto()

    #: Signatures::Count_Signature
    #: (present if base/frameworks/signatures/main.zeek is loaded)
    #: The same signature has triggered multiple times for a host.
    #: The number of times the signature has been triggered is
    #: defined by the Signatures::count\_thresholds
    #: variable. To generate this notice, the
    #: Signatures::SIG\_COUNT\_PER\_RESP action must be
    #: set for the signature.
    Type['Signatures__Count_Signature'] = enum.auto()

    #: Signatures::Signature_Summary
    #: (present if base/frameworks/signatures/main.zeek is loaded)
    #: Summarize the number of times a host triggered a signature.
    #: The interval between summaries is defined by the
    #: Signatures::summary\_interval variable.
    Type['Signatures__Signature_Summary'] = enum.auto()

    #: PacketFilter::Compile_Failure
    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    #: This notice is generated if a packet filter cannot be compiled.
    Type['PacketFilter__Compile_Failure'] = enum.auto()

    #: PacketFilter::Install_Failure
    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    #: Generated if a packet filter fails to install.
    Type['PacketFilter__Install_Failure'] = enum.auto()

    #: PacketFilter::Too_Long_To_Compile_Filter
    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    #: Generated when a notice takes too long to compile.
    Type['PacketFilter__Too_Long_To_Compile_Filter'] = enum.auto()

    #: PacketFilter::Dropped_Packets
    #: (present if base/frameworks/packet-filter/netstats.zeek is loaded)
    #: Indicates packets were dropped by the packet filter.
    Type['PacketFilter__Dropped_Packets'] = enum.auto()

    #: ProtocolDetector::Protocol_Found
    #: (present if policy/frameworks/dpd/detect-protocols.zeek is loaded)
    Type['ProtocolDetector__Protocol_Found'] = enum.auto()

    #: ProtocolDetector::Server_Found
    #: (present if policy/frameworks/dpd/detect-protocols.zeek is loaded)
    Type['ProtocolDetector__Server_Found'] = enum.auto()

    #: Intel::Notice
    #: (present if policy/frameworks/intel/do\_notice.zeek is loaded)
    #: This notice is generated when an intelligence
    #: indicator is denoted to be notice-worthy.
    Type['Intel__Notice'] = enum.auto()

    #: TeamCymruMalwareHashRegistry::Match
    #: (present if policy/frameworks/files/detect-MHR.zeek is loaded)
    #: The hash value of a file transferred over HTTP matched in the
    #: malware hash registry.
    Type['TeamCymruMalwareHashRegistry__Match'] = enum.auto()

    #: PacketFilter::No_More_Conn_Shunts_Available
    #: (present if policy/frameworks/packet-filter/shunt.zeek is loaded)
    #: Indicative that PacketFilter::max\_bpf\_shunts
    #: connections are already being shunted with BPF filters and
    #: no more are allowed.
    Type['PacketFilter__No_More_Conn_Shunts_Available'] = enum.auto()

    #: PacketFilter::Cannot_BPF_Shunt_Conn
    #: (present if policy/frameworks/packet-filter/shunt.zeek is loaded)
    #: Limitations in BPF make shunting some connections with BPF
    #: impossible.  This notice encompasses those various cases.
    Type['PacketFilter__Cannot_BPF_Shunt_Conn'] = enum.auto()

    #: Software::Software_Version_Change
    #: (present if policy/frameworks/software/version-changes.zeek is loaded)
    #: For certain software, a version changing may matter.  In that
    #: case, this notice will be generated.  Software that matters
    #: if the version changes can be configured with the
    #: Software::interesting\_version\_changes variable.
    Type['Software__Software_Version_Change'] = enum.auto()

    #: Software::Vulnerable_Version
    #: (present if policy/frameworks/software/vulnerable.zeek is loaded)
    #: Indicates that a vulnerable version of software was detected.
    Type['Software__Vulnerable_Version'] = enum.auto()

    #: CaptureLoss::Too_Much_Loss
    #: (present if policy/misc/capture-loss.zeek is loaded)
    #: Report if the detected capture loss exceeds the percentage
    #: threshold.
    Type['CaptureLoss__Too_Much_Loss'] = enum.auto()

    #: Traceroute::Detected
    #: (present if policy/misc/detect-traceroute/main.zeek is loaded)
    #: Indicates that a host was seen running traceroutes.  For more
    #: detail about specific traceroutes that we run, refer to the
    #: traceroute.log.
    Type['Traceroute__Detected'] = enum.auto()

    #: Scan::Address_Scan
    #: (present if policy/misc/scan.zeek is loaded)
    #: Address scans detect that a host appears to be scanning some
    #: number of destinations on a single port. This notice is
    #: generated when more than Scan::addr\_scan\_threshold
    #: unique hosts are seen over the previous
    #: Scan::addr\_scan\_interval time range.
    Type['Scan__Address_Scan'] = enum.auto()

    #: Scan::Port_Scan
    #: (present if policy/misc/scan.zeek is loaded)
    #: Port scans detect that an attacking host appears to be
    #: scanning a single victim host on several ports.  This notice
    #: is generated when an attacking host attempts to connect to
    #: Scan::port\_scan\_threshold
    #: unique ports on a single host over the previous
    #: Scan::port\_scan\_interval time range.
    Type['Scan__Port_Scan'] = enum.auto()

    #: Conn::Retransmission_Inconsistency
    #: (present if policy/protocols/conn/weirds.zeek is loaded)
    #: Possible evasion; usually just chud.
    Type['Conn__Retransmission_Inconsistency'] = enum.auto()

    #: Conn::Content_Gap
    #: (present if policy/protocols/conn/weirds.zeek is loaded)
    #: Data has sequence hole; perhaps due to filtering.
    Type['Conn__Content_Gap'] = enum.auto()

    #: DNS::External_Name
    #: (present if policy/protocols/dns/detect-external-names.zeek is loaded)
    #: Raised when a non-local name is found to be pointing at a
    #: local host.  The Site::local\_zones variable
    #: must be set appropriately for this detection.
    Type['DNS__External_Name'] = enum.auto()

    #: FTP::Bruteforcing
    #: (present if policy/protocols/ftp/detect-bruteforcing.zeek is loaded)
    #: Indicates a host bruteforcing FTP logins by watching for too
    #: many rejected usernames or failed passwords.
    Type['FTP__Bruteforcing'] = enum.auto()

    #: FTP::Site_Exec_Success
    #: (present if policy/protocols/ftp/detect.zeek is loaded)
    #: Indicates that a successful response to a “SITE EXEC”
    #: command/arg pair was seen.
    Type['FTP__Site_Exec_Success'] = enum.auto()

    #: HTTP::SQL_Injection_Attacker
    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicates that a host performing SQL injection attacks was
    #: detected.
    Type['HTTP__SQL_Injection_Attacker'] = enum.auto()

    #: HTTP::SQL_Injection_Victim
    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicates that a host was seen to have SQL injection attacks
    #: against it.  This is tracked by IP address as opposed to
    #: hostname.
    Type['HTTP__SQL_Injection_Victim'] = enum.auto()

    #: SMTP::Blocklist_Error_Message
    #: (present if policy/protocols/smtp/blocklists.zeek is loaded)
    #: An SMTP server sent a reply mentioning an SMTP block list.
    Type['SMTP__Blocklist_Error_Message'] = enum.auto()

    #: SMTP::Blocklist_Blocked_Host
    #: (present if policy/protocols/smtp/blocklists.zeek is loaded)
    #: The originator’s address is seen in the block list error message.
    #: This is useful to detect local hosts sending SPAM with a high
    #: positive rate.
    Type['SMTP__Blocklist_Blocked_Host'] = enum.auto()

    #: SMTP::Suspicious_Origination
    #: (present if policy/protocols/smtp/detect-suspicious-orig.zeek is loaded)
    Type['SMTP__Suspicious_Origination'] = enum.auto()

    #: SSH::Password_Guessing
    #: (present if policy/protocols/ssh/detect-bruteforcing.zeek is loaded)
    #: Indicates that a host has been identified as crossing the
    #: SSH::password\_guesses\_limit threshold with
    #: failed logins.
    Type['SSH__Password_Guessing'] = enum.auto()

    #: SSH::Login_By_Password_Guesser
    #: (present if policy/protocols/ssh/detect-bruteforcing.zeek is loaded)
    #: Indicates that a host previously identified as a “password
    #: guesser” has now had a successful login
    #: attempt. This is not currently implemented.
    Type['SSH__Login_By_Password_Guesser'] = enum.auto()

    #: SSH::Watched_Country_Login
    #: (present if policy/protocols/ssh/geo-data.zeek is loaded)
    #: If an SSH login is seen to or from a “watched” country based
    #: on the SSH::watched\_countries variable then this
    #: notice will be generated.
    Type['SSH__Watched_Country_Login'] = enum.auto()

    #: SSH::Interesting_Hostname_Login
    #: (present if policy/protocols/ssh/interesting-hostnames.zeek is loaded)
    #: Generated if a login originates or responds with a host where
    #: the reverse hostname lookup resolves to a name matched by the
    #: SSH::interesting\_hostnames regular expression.
    Type['SSH__Interesting_Hostname_Login'] = enum.auto()

    #: SSL::Certificate_Expired
    #: (present if policy/protocols/ssl/expiring-certs.zeek is loaded)
    #: Indicates that a certificate’s NotValidAfter date has lapsed
    #: and the certificate is now invalid.
    Type['SSL__Certificate_Expired'] = enum.auto()

    #: SSL::Certificate_Expires_Soon
    #: (present if policy/protocols/ssl/expiring-certs.zeek is loaded)
    #: Indicates that a certificate is going to expire within
    #: SSL::notify\_when\_cert\_expiring\_in.
    Type['SSL__Certificate_Expires_Soon'] = enum.auto()

    #: SSL::Certificate_Not_Valid_Yet
    #: (present if policy/protocols/ssl/expiring-certs.zeek is loaded)
    #: Indicates that a certificate’s NotValidBefore date is future
    #: dated.
    Type['SSL__Certificate_Not_Valid_Yet'] = enum.auto()

    #: Heartbleed::SSL_Heartbeat_Attack
    #: (present if policy/protocols/ssl/heartbleed.zeek is loaded)
    #: Indicates that a host performed a heartbleed attack or scan.
    Type['Heartbleed__SSL_Heartbeat_Attack'] = enum.auto()

    #: Heartbleed::SSL_Heartbeat_Attack_Success
    #: (present if policy/protocols/ssl/heartbleed.zeek is loaded)
    #: Indicates that a host performing a heartbleed attack was probably successful.
    Type['Heartbleed__SSL_Heartbeat_Attack_Success'] = enum.auto()

    #: Heartbleed::SSL_Heartbeat_Odd_Length
    #: (present if policy/protocols/ssl/heartbleed.zeek is loaded)
    #: Indicates we saw heartbeat requests with odd length. Probably an attack or scan.
    Type['Heartbleed__SSL_Heartbeat_Odd_Length'] = enum.auto()

    #: Heartbleed::SSL_Heartbeat_Many_Requests
    #: (present if policy/protocols/ssl/heartbleed.zeek is loaded)
    #: Indicates we saw many heartbeat requests without a reply. Might be an attack.
    Type['Heartbleed__SSL_Heartbeat_Many_Requests'] = enum.auto()

    #: SSL::Invalid_Server_Cert
    #: (present if policy/protocols/ssl/validate-certs.zeek is loaded)
    #: This notice indicates that the result of validating the
    #: certificate along with its full certificate chain was
    #: invalid.
    Type['SSL__Invalid_Server_Cert'] = enum.auto()

    #: SSL::Invalid_Ocsp_Response
    #: (present if policy/protocols/ssl/validate-ocsp.zeek is loaded)
    #: This indicates that the OCSP response was not deemed
    #: to be valid.
    Type['SSL__Invalid_Ocsp_Response'] = enum.auto()

    #: SSL::Weak_Key
    #: (present if policy/protocols/ssl/weak-keys.zeek is loaded)
    #: Indicates that a server is using a potentially unsafe key.
    Type['SSL__Weak_Key'] = enum.auto()

    #: SSL::Old_Version
    #: (present if policy/protocols/ssl/weak-keys.zeek is loaded)
    #: Indicates that a server is using a potentially unsafe version
    Type['SSL__Old_Version'] = enum.auto()

    #: SSL::Weak_Cipher
    #: (present if policy/protocols/ssl/weak-keys.zeek is loaded)
    #: Indicates that a server is using a potentially unsafe cipher
    Type['SSL__Weak_Cipher'] = enum.auto()

    #: ZeekygenExample::Zeekygen_One
    #: (present if zeekygen/example.zeek is loaded)
    #: Any number of this type of comment
    #: will document “Zeekygen\_One”.
    Type['ZeekygenExample__Zeekygen_One'] = enum.auto()

    #: ZeekygenExample::Zeekygen_Two
    #: (present if zeekygen/example.zeek is loaded)
    #: Any number of this type of comment
    #: will document “ZEEKYGEN\_TWO”.
    Type['ZeekygenExample__Zeekygen_Two'] = enum.auto()

    #: ZeekygenExample::Zeekygen_Three
    #: (present if zeekygen/example.zeek is loaded)
    Type['ZeekygenExample__Zeekygen_Three'] = enum.auto()

    #: ZeekygenExample::Zeekygen_Four
    #: (present if zeekygen/example.zeek is loaded)
    #: Omitting comments is fine, and so is mixing ## and ##<, but
    #: it’s probably best to use only one style consistently.
    Type['ZeekygenExample__Zeekygen_Four'] = enum.auto()
