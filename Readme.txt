Parse snort signatures and outputs the parsed signatures as json

USAGE:
        python rulesparser.py --outfile rules.json --debug --logfile rules.log ../etpro_rules/rules/ ../nhc_ids_rules/rules/

EXAMPLE OUTPUT:

[
    {
        "comment": "by Matt Jonkman",
        "filename": "worm.rules",
        "linenum": 46,
        "sigtype": "snort",
        "enabled": false,
        "sig": "alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET WORM Allaple ICMP Sweep Ping Outbound\"; icode:0; itype:8; content:\"Babcdefghijklmnopqrstuvwabcdefghi\"; threshold: type both, count 1, seconds 60, track by_src; reference:url,www.sophos.com/virusinfo/analyses/w32allapleb.html; reference:url,isc.sans.org/diary.html?storyid=2451; reference:url,doc.emergingthreats.net/2003292; classtype:trojan-activity; sid:2003292; rev:7;)",
        "action": "alert",
        "proto": "icmp",
        "src_ip": "$HOME_NET",
        "src_port": "any",
        "dir": "->",
        "dest_ip": "$EXTERNAL_NET",
        "dest_port": "any",
        "stripped_options": "icode:0; itype:8; content:\"Babcdefghijklmnopqrstuvwabcdefghi\"; threshold:type both, count 1, seconds 60, track by_src; ",
        "reference": [
            "url,www.sophos.com/virusinfo/analyses/w32allapleb.html",
            "url,isc.sans.org/diary.html?storyid=2451",
            "url,doc.emergingthreats.net/2003292"
        ],
        "rev": "7",
        "sid": "2003292",
        "classtype": "trojan-activity"
    },
...
]

WEB
The old web code is not updated to work with the new json output. A new import tool needs to be written. preferably for a json database like RethinkDB or elasticsearch
Screenshots form the old web http://grodaas.wordpress.com/2010/08/30/managing-snort-signatures/
