using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Web;

namespace FortiShell {
	
    public class Policy {
        public int Edit;
        public int Number;
        
        public string SourceInterface;
        public string DestinationInterface;
        
        public string SourceAddress;
        public string DestinationAddress;
        public string Action;
        public string Schedule;
        public List<string> Service;
        public bool Inbound;
        public bool Outbound;
        public string VpnTunnel;
        public bool Disabled;
        public bool ProfileStatus;
        public bool LogTraffic;
        public bool NatEnabled;
        public bool NatInbound;
        public string Profile;
        public string Uuid;
        public string Comments;
        
        public string TrafficShaper;
        public string TrafficShaperReverse;
        
        public string WebFilterProfile;
        public string VoipProfile;
        public string SslSshProfile;
        public string SpamFilterProfile;
    }
}