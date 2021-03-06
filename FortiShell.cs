using System;
using System.Xml;
using System.Web;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Net.Security;
using System.IO;
using System.Collections.Generic;
namespace FortiShell {
	
    public class Address {
		public string Name;
		public string Value;
		public string Interface;
    }
	
    public class AddressGroup {
		public string Name;
		public List<string> Value;
		public string Comment;
		public string Uuid;
    }
	
    public class Policy {
        public int Edit;
        public int Number;
        
        public List<string> SourceInterface;
        public List<string> DestinationInterface;
        
        public List<string> SourceAddress;
        public List<string> DestinationAddress;
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
        public string ProfileProtocolOptions;
        public string Avprofile;
        
        public string ApplicationList;
        
        public string DlpSensor;
        public string IpsSensor;
        
        public bool UtmStatus;
        
    }
	
    public class Route {
		public string Type;
		public string Interface;
		public string Destination;
		public string NextHop;
		public int Number;
    }
	
    public class Service {
		public string Name;
		public List<string> Value;
		public string Comment;
		public string Category;
    }
	
    public class ServiceGroup {
		public string Name;
		public List<string> Value;
    }
	
    public class Vip {
		public string Name;
		public string ExternalInterface;
		public string ExternalIp;
		public string MappedIp;
    }
}
