# -*- coding: utf-8 -*-
"""Namespace: Notice.

:module: zlogging.enum.Notice
"""

from zlogging._compat import enum


@enum.unique
class Action(enum.IntFlag):
    """These are values representing actions that can be taken with notices.

    c.f. `base/frameworks/notice/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/notice/main.zeek.html>`__

    """

    _ignore_ = 'Action _'
    Action = vars()

    #: Indicates that there is no action to be taken.
    #: :currentmodule: zlogging.enum.Notice
    Action['ACTION_NONE'] = enum.auto()

    #: Indicates that the notice should be sent to the notice
    #: logging stream.
    #: :currentmodule: zlogging.enum.Notice
    Action['ACTION_LOG'] = enum.auto()

    #: Indicates that the notice should be sent to the email
    #: address(es) configured in the Notice::mail_dest
    #: variable.
    #: :currentmodule: zlogging.enum.Notice
    Action['ACTION_EMAIL'] = enum.auto()

    #: Indicates that the notice should be alarmed.  A readable
    #: ASCII version of the alarm log is emailed in bulk to the
    #: address(es) configured in Notice::mail_dest.
    #: :currentmodule: zlogging.enum.Notice
    Action['ACTION_ALARM'] = enum.auto()

    #: (present if base/frameworks/notice/actions/email_admin.zeek is loaded)
    #: Indicate that the generated email should be addressed to the
    #: appropriate email addresses as found by the
    #: Site::get_emails function based on the relevant
    #: address or addresses indicated in the notice.
    #: :currentmodule: zlogging.enum.Notice
    Action['ACTION_EMAIL_ADMIN'] = enum.auto()

    #: (present if base/frameworks/notice/actions/page.zeek is loaded)
    #: Indicates that the notice should be sent to the pager email
    #: address configured in the Notice::mail_page_dest
    #: variable.
    #: :currentmodule: zlogging.enum.Notice
    Action['ACTION_PAGE'] = enum.auto()

    #: (present if base/frameworks/notice/actions/add-geodata.zeek is loaded)
    #: Indicates that the notice should have geodata added for the
    #: “remote” host.  Site::local_nets must be defined
    #: in order for this to work.
    #: :currentmodule: zlogging.enum.Notice
    Action['ACTION_ADD_GEODATA'] = enum.auto()

    #: (present if policy/frameworks/notice/actions/drop.zeek is loaded)
    #: Drops the address via NetControl::drop_address_catch_release.
    #: :currentmodule: zlogging.enum.Notice
    Action['ACTION_DROP'] = enum.auto()


@enum.unique
class Type(enum.IntFlag):
    """Scripts creating new notices need to redef this enum to add their
    own specific notice types which would then get used when they call
    the NOTICE function.  The convention is to give a general
    category along with the specific notice separating words with
    underscores and using leading capitals on each word except for
    abbreviations which are kept in all capitals. For example,
    SSH::Password_Guessing is for hosts that have crossed a threshold of
    failed SSH logins.

    c.f. `base/frameworks/notice/main.zeek <https://docs.zeek.org/en/stable/scripts/base/frameworks/notice/main.zeek.html>`__

    """

    _ignore_ = 'Type _'
    Type = vars()

    #: Notice reporting a count of how often a notice occurred.
    #: :currentmodule: zlogging.enum.Notice
    Type['Tally'] = enum.auto()

    #: (present if base/frameworks/notice/weird.zeek is loaded)
    #: Generic unusual but notice-worthy weird activity.
    #: :currentmodule: zlogging.enum.Notice
    Type['Weird::Activity'] = enum.auto()

    #: (present if base/frameworks/signatures/main.zeek is loaded)
    #: Generic notice type for notice-worthy signature matches.
    #: :currentmodule: zlogging.enum.Notice
    Type['Signatures::Sensitive_Signature'] = enum.auto()

    #: (present if base/frameworks/signatures/main.zeek is loaded)
    #: Host has triggered many signatures on the same host.  The
    #: number of signatures is defined by the
    #: Signatures::vert_scan_thresholds variable.
    #: :currentmodule: zlogging.enum.Notice
    Type['Signatures::Multiple_Signatures'] = enum.auto()

    #: (present if base/frameworks/signatures/main.zeek is loaded)
    #: Host has triggered the same signature on multiple hosts as
    #: defined by the Signatures::horiz_scan_thresholds
    #: variable.
    #: :currentmodule: zlogging.enum.Notice
    Type['Signatures::Multiple_Sig_Responders'] = enum.auto()

    #: (present if base/frameworks/signatures/main.zeek is loaded)
    #: The same signature has triggered multiple times for a host.
    #: The number of times the signature has been triggered is
    #: defined by the Signatures::count_thresholds
    #: variable. To generate this notice, the
    #: Signatures::SIG_COUNT_PER_RESP action must be
    #: set for the signature.
    #: :currentmodule: zlogging.enum.Notice
    Type['Signatures::Count_Signature'] = enum.auto()

    #: (present if base/frameworks/signatures/main.zeek is loaded)
    #: Summarize the number of times a host triggered a signature.
    #: The interval between summaries is defined by the
    #: Signatures::summary_interval variable.
    #: :currentmodule: zlogging.enum.Notice
    Type['Signatures::Signature_Summary'] = enum.auto()

    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    #: This notice is generated if a packet filter cannot be compiled.
    #: :currentmodule: zlogging.enum.Notice
    Type['PacketFilter::Compile_Failure'] = enum.auto()

    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    #: Generated if a packet filter fails to install.
    #: :currentmodule: zlogging.enum.Notice
    Type['PacketFilter::Install_Failure'] = enum.auto()

    #: (present if base/frameworks/packet-filter/main.zeek is loaded)
    #: Generated when a notice takes too long to compile.
    #: :currentmodule: zlogging.enum.Notice
    Type['PacketFilter::Too_Long_To_Compile_Filter'] = enum.auto()

    #: (present if base/frameworks/packet-filter/netstats.zeek is loaded)
    #: Indicates packets were dropped by the packet filter.
    #: :currentmodule: zlogging.enum.Notice
    Type['PacketFilter::Dropped_Packets'] = enum.auto()

    #: (present if policy/frameworks/dpd/detect-protocols.zeek is loaded)
    #: :currentmodule: zlogging.enum.Notice
    Type['ProtocolDetector::Protocol_Found'] = enum.auto()

    #: (present if policy/frameworks/dpd/detect-protocols.zeek is loaded)
    #: :currentmodule: zlogging.enum.Notice
    Type['ProtocolDetector::Server_Found'] = enum.auto()

    #: (present if policy/frameworks/intel/do_notice.zeek is loaded)
    #: This notice is generated when an intelligence
    #: indicator is denoted to be notice-worthy.
    #: :currentmodule: zlogging.enum.Notice
    Type['Intel::Notice'] = enum.auto()

    #: (present if policy/frameworks/files/detect-MHR.zeek is loaded)
    #: The hash value of a file transferred over HTTP matched in the
    #: malware hash registry.
    #: :currentmodule: zlogging.enum.Notice
    Type['TeamCymruMalwareHashRegistry::Match'] = enum.auto()

    #: (present if policy/frameworks/packet-filter/shunt.zeek is loaded)
    #: Indicative that PacketFilter::max_bpf_shunts
    #: connections are already being shunted with BPF filters and
    #: no more are allowed.
    #: :currentmodule: zlogging.enum.Notice
    Type['PacketFilter::No_More_Conn_Shunts_Available'] = enum.auto()

    #: (present if policy/frameworks/packet-filter/shunt.zeek is loaded)
    #: Limitations in BPF make shunting some connections with BPF
    #: impossible.  This notice encompasses those various cases.
    #: :currentmodule: zlogging.enum.Notice
    Type['PacketFilter::Cannot_BPF_Shunt_Conn'] = enum.auto()

    #: (present if policy/frameworks/software/version-changes.zeek is loaded)
    #: For certain software, a version changing may matter.  In that
    #: case, this notice will be generated.  Software that matters
    #: if the version changes can be configured with the
    #: Software::interesting_version_changes variable.
    #: :currentmodule: zlogging.enum.Notice
    Type['Software::Software_Version_Change'] = enum.auto()

    #: (present if policy/frameworks/software/vulnerable.zeek is loaded)
    #: Indicates that a vulnerable version of software was detected.
    #: :currentmodule: zlogging.enum.Notice
    Type['Software::Vulnerable_Version'] = enum.auto()

    #: (present if policy/misc/capture-loss.zeek is loaded)
    #: Report if the detected capture loss exceeds the percentage
    #: threshold.
    #: :currentmodule: zlogging.enum.Notice
    Type['CaptureLoss::Too_Much_Loss'] = enum.auto()

    #: (present if policy/misc/detect-traceroute/main.zeek is loaded)
    #: Indicates that a host was seen running traceroutes.  For more
    #: detail about specific traceroutes that we run, refer to the
    #: traceroute.log.
    #: :currentmodule: zlogging.enum.Notice
    Type['Traceroute::Detected'] = enum.auto()

    #: (present if policy/misc/scan.zeek is loaded)
    #: Address scans detect that a host appears to be scanning some
    #: number of destinations on a single port. This notice is
    #: generated when more than Scan::addr_scan_threshold
    #: unique hosts are seen over the previous
    #: Scan::addr_scan_interval time range.
    #: :currentmodule: zlogging.enum.Notice
    Type['Scan::Address_Scan'] = enum.auto()

    #: (present if policy/misc/scan.zeek is loaded)
    #: Port scans detect that an attacking host appears to be
    #: scanning a single victim host on several ports.  This notice
    #: is generated when an attacking host attempts to connect to
    #: Scan::port_scan_threshold
    #: unique ports on a single host over the previous
    #: Scan::port_scan_interval time range.
    #: :currentmodule: zlogging.enum.Notice
    Type['Scan::Port_Scan'] = enum.auto()

    #: (present if policy/protocols/conn/weirds.zeek is loaded)
    #: Possible evasion; usually just chud.
    #: :currentmodule: zlogging.enum.Notice
    Type['Conn::Retransmission_Inconsistency'] = enum.auto()

    #: (present if policy/protocols/conn/weirds.zeek is loaded)
    #: Data has sequence hole; perhaps due to filtering.
    #: :currentmodule: zlogging.enum.Notice
    Type['Conn::Content_Gap'] = enum.auto()

    #: (present if policy/protocols/dns/detect-external-names.zeek is loaded)
    #: Raised when a non-local name is found to be pointing at a
    #: local host.  The Site::local_zones variable
    #: must be set appropriately for this detection.
    #: :currentmodule: zlogging.enum.Notice
    Type['DNS::External_Name'] = enum.auto()

    #: (present if policy/protocols/ftp/detect-bruteforcing.zeek is loaded)
    #: Indicates a host bruteforcing FTP logins by watching for too
    #: many rejected usernames or failed passwords.
    #: :currentmodule: zlogging.enum.Notice
    Type['FTP::Bruteforcing'] = enum.auto()

    #: (present if policy/protocols/ftp/detect.zeek is loaded)
    #: Indicates that a successful response to a “SITE EXEC”
    #: command/arg pair was seen.
    #: :currentmodule: zlogging.enum.Notice
    Type['FTP::Site_Exec_Success'] = enum.auto()

    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicates that a host performing SQL injection attacks was
    #: detected.
    #: :currentmodule: zlogging.enum.Notice
    Type['HTTP::SQL_Injection_Attacker'] = enum.auto()

    #: (present if policy/protocols/http/detect-sqli.zeek is loaded)
    #: Indicates that a host was seen to have SQL injection attacks
    #: against it.  This is tracked by IP address as opposed to
    #: hostname.
    #: :currentmodule: zlogging.enum.Notice
    Type['HTTP::SQL_Injection_Victim'] = enum.auto()

    #: (present if policy/protocols/smtp/blocklists.zeek is loaded)
    #: An SMTP server sent a reply mentioning an SMTP block list.
    #: :currentmodule: zlogging.enum.Notice
    Type['SMTP::Blocklist_Error_Message'] = enum.auto()

    #: (present if policy/protocols/smtp/blocklists.zeek is loaded)
    #: The originator’s address is seen in the block list error message.
    #: This is useful to detect local hosts sending SPAM with a high
    #: positive rate.
    #: :currentmodule: zlogging.enum.Notice
    Type['SMTP::Blocklist_Blocked_Host'] = enum.auto()

    #: (present if policy/protocols/smtp/detect-suspicious-orig.zeek is loaded)
    #: :currentmodule: zlogging.enum.Notice
    Type['SMTP::Suspicious_Origination'] = enum.auto()

    #: (present if policy/protocols/ssh/detect-bruteforcing.zeek is loaded)
    #: Indicates that a host has been identified as crossing the
    #: SSH::password_guesses_limit threshold with
    #: failed logins.
    #: :currentmodule: zlogging.enum.Notice
    Type['SSH::Password_Guessing'] = enum.auto()

    #: (present if policy/protocols/ssh/detect-bruteforcing.zeek is loaded)
    #: Indicates that a host previously identified as a “password
    #: guesser” has now had a successful login
    #: attempt. This is not currently implemented.
    #: :currentmodule: zlogging.enum.Notice
    Type['SSH::Login_By_Password_Guesser'] = enum.auto()

    #: (present if policy/protocols/ssh/geo-data.zeek is loaded)
    #: If an SSH login is seen to or from a “watched” country based
    #: on the SSH::watched_countries variable then this
    #: notice will be generated.
    #: :currentmodule: zlogging.enum.Notice
    Type['SSH::Watched_Country_Login'] = enum.auto()

    #: (present if policy/protocols/ssh/interesting-hostnames.zeek is loaded)
    #: Generated if a login originates or responds with a host where
    #: the reverse hostname lookup resolves to a name matched by the
    #: SSH::interesting_hostnames regular expression.
    #: :currentmodule: zlogging.enum.Notice
    Type['SSH::Interesting_Hostname_Login'] = enum.auto()

    #: (present if policy/protocols/ssl/expiring-certs.zeek is loaded)
    #: Indicates that a certificate’s NotValidAfter date has lapsed
    #: and the certificate is now invalid.
    #: :currentmodule: zlogging.enum.Notice
    Type['SSL::Certificate_Expired'] = enum.auto()

    #: (present if policy/protocols/ssl/expiring-certs.zeek is loaded)
    #: Indicates that a certificate is going to expire within
    #: SSL::notify_when_cert_expiring_in.
    #: :currentmodule: zlogging.enum.Notice
    Type['SSL::Certificate_Expires_Soon'] = enum.auto()

    #: (present if policy/protocols/ssl/expiring-certs.zeek is loaded)
    #: Indicates that a certificate’s NotValidBefore date is future
    #: dated.
    #: :currentmodule: zlogging.enum.Notice
    Type['SSL::Certificate_Not_Valid_Yet'] = enum.auto()

    #: (present if policy/protocols/ssl/heartbleed.zeek is loaded)
    #: Indicates that a host performed a heartbleed attack or scan.
    #: :currentmodule: zlogging.enum.Notice
    Type['Heartbleed::SSL_Heartbeat_Attack'] = enum.auto()

    #: (present if policy/protocols/ssl/heartbleed.zeek is loaded)
    #: Indicates that a host performing a heartbleed attack was probably successful.
    #: :currentmodule: zlogging.enum.Notice
    Type['Heartbleed::SSL_Heartbeat_Attack_Success'] = enum.auto()

    #: (present if policy/protocols/ssl/heartbleed.zeek is loaded)
    #: Indicates we saw heartbeat requests with odd length. Probably an attack or scan.
    #: :currentmodule: zlogging.enum.Notice
    Type['Heartbleed::SSL_Heartbeat_Odd_Length'] = enum.auto()

    #: (present if policy/protocols/ssl/heartbleed.zeek is loaded)
    #: Indicates we saw many heartbeat requests without a reply. Might be an attack.
    #: :currentmodule: zlogging.enum.Notice
    Type['Heartbleed::SSL_Heartbeat_Many_Requests'] = enum.auto()

    #: (present if policy/protocols/ssl/validate-certs.zeek is loaded)
    #: This notice indicates that the result of validating the
    #: certificate along with its full certificate chain was
    #: invalid.
    #: :currentmodule: zlogging.enum.Notice
    Type['SSL::Invalid_Server_Cert'] = enum.auto()

    #: (present if policy/protocols/ssl/validate-ocsp.zeek is loaded)
    #: This indicates that the OCSP response was not deemed
    #: to be valid.
    #: :currentmodule: zlogging.enum.Notice
    Type['SSL::Invalid_Ocsp_Response'] = enum.auto()

    #: (present if policy/protocols/ssl/weak-keys.zeek is loaded)
    #: Indicates that a server is using a potentially unsafe key.
    #: :currentmodule: zlogging.enum.Notice
    Type['SSL::Weak_Key'] = enum.auto()

    #: (present if policy/protocols/ssl/weak-keys.zeek is loaded)
    #: Indicates that a server is using a potentially unsafe version
    #: :currentmodule: zlogging.enum.Notice
    Type['SSL::Old_Version'] = enum.auto()

    #: (present if policy/protocols/ssl/weak-keys.zeek is loaded)
    #: Indicates that a server is using a potentially unsafe cipher
    #: :currentmodule: zlogging.enum.Notice
    Type['SSL::Weak_Cipher'] = enum.auto()

    #: (present if zeekygen/example.zeek is loaded)
    #: Any number of this type of comment
    #: will document “Zeekygen_One”.
    #: :currentmodule: zlogging.enum.Notice
    Type['ZeekygenExample::Zeekygen_One'] = enum.auto()

    #: (present if zeekygen/example.zeek is loaded)
    #: Any number of this type of comment
    #: will document “ZEEKYGEN_TWO”.
    #: :currentmodule: zlogging.enum.Notice
    Type['ZeekygenExample::Zeekygen_Two'] = enum.auto()

    #: (present if zeekygen/example.zeek is loaded)
    #: :currentmodule: zlogging.enum.Notice
    Type['ZeekygenExample::Zeekygen_Three'] = enum.auto()

    #: (present if zeekygen/example.zeek is loaded)
    #: Omitting comments is fine, and so is mixing ## and ##<, but
    #: it’s probably best to use only one style consistently.
    #: :currentmodule: zlogging.enum.Notice
    Type['ZeekygenExample::Zeekygen_Four'] = enum.auto()
