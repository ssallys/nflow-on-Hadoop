package nflow.hadoop.analyzer.lib;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.apache.hadoop.record.Buffer;

import p3.common.lib.BinaryUtils;
import p3.common.lib.Bytes;
import p3.common.lib.EZBytes;

/** This class represents TCP packet. */
//public class PacketStatWritable extends IPPacket implements WritableComparable<PacketStatWritable>
public class FlowWritable extends org.apache.hadoop.record.Record
{
	public static final int MIN_PKT_SIZE = 42;	
	public static final int PCAP_FILE_HEADER_LENGTH = 24;  
	
	public static int PCAP_HLEN = 16;
	public static int PCAP_ETHER_IP_UDP_HLEN = PCAP_HLEN+42;
	public static int CFLOW_HLEN = 24;	
	public static int FLOW_LEN = 48;
	
	static class NetFlow{
		public static final int[] SRCADDR = {0,4};
		public static final int[] DSTADDR = {4,4} ;
		public static final int[] NEXTHOP = {8,4};
		public static final int[] INPUT = {12,2};
		public static final int[] OUTPUT = {14,2};
		public static final int[] DPKTS = {16,4};
		public static final int[] DOCTETS = {20,4};
		public static final int[] FIRST = {24,4};		
		public static final int[] LAST = {28,4};
		public static final int[] SRCPORT = {32,2};	
		public static final int[] DSTPORT = {34,2};	
		public static final int[] PAD1 = {36,1};	
		public static final int[] TCP_FLAGS = {37,1};	
		public static final int[] PROT = {38,1};	
		public static final int[] TOS = {39,1};	
		public static final int[] SRC_AS = {40,2};	
		public static final int[] DST_AS = {42,2};	
		public static final int[] SRC_MASK = {44,1};	
		public static final int[] DST_MASK = {45,1};	
		public static final int[] PAD2 = {46,2};	
	}

	protected static final org.apache.hadoop.record.meta.RecordTypeInfo _rio_recTypeInfo;
	protected static org.apache.hadoop.record.meta.RecordTypeInfo _rio_rtiFilter;
	protected static int[] _rio_rtiFilterFields;
	static {
		_rio_recTypeInfo = new org.apache.hadoop.record.meta.RecordTypeInfo("Flows");
		
		_rio_recTypeInfo.addField("sys_uptime", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("timestamp", org.apache.hadoop.record.meta.TypeID.LongTypeID);	
		_rio_recTypeInfo.addField("srcaddr", org.apache.hadoop.record.meta.TypeID.StringTypeID);
		_rio_recTypeInfo.addField("dstaddr", org.apache.hadoop.record.meta.TypeID.StringTypeID);
		_rio_recTypeInfo.addField("nexthop", org.apache.hadoop.record.meta.TypeID.StringTypeID);
		_rio_recTypeInfo.addField("input", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("output", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("dPkts", org.apache.hadoop.record.meta.TypeID.LongTypeID);//
		_rio_recTypeInfo.addField("dOctets", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("first", org.apache.hadoop.record.meta.TypeID.LongTypeID);
		_rio_recTypeInfo.addField("last", org.apache.hadoop.record.meta.TypeID.LongTypeID);		
		_rio_recTypeInfo.addField("srcport", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("dstport", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("pad1", org.apache.hadoop.record.meta.TypeID.IntTypeID);	
		_rio_recTypeInfo.addField("tcp_flags", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("prot", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("tos", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("src_as", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("dst_as", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("src_mask", org.apache.hadoop.record.meta.TypeID.IntTypeID);
		_rio_recTypeInfo.addField("dst_mask", org.apache.hadoop.record.meta.TypeID.IntTypeID);	
		_rio_recTypeInfo.addField("pad2", org.apache.hadoop.record.meta.TypeID.IntTypeID);

		_rio_recTypeInfo.addField("orderby", org.apache.hadoop.record.meta.TypeID.BufferTypeID);
	}

	protected static final long serialVersionUID = -8856988406589484129L;
	
	EZBytes eb;

	protected long sys_uptime;
	protected long timestamp;

	protected String srcaddr;
	protected String dstaddr;
	protected int src_as;
	protected int dst_as;
	protected int srcport;
	protected int dstport;

	protected long dPkts;
	protected String nexthop;
	protected int input;
	protected int output;

	protected int pad1;
	protected long dOctets;
	protected int src_mask;
	protected int dst_mask;
	protected int tcp_flags;
	protected int prot;
	protected int tos;
	protected int pad2;
	protected long first;
	protected long last;
	protected Buffer orderby;
	
	protected String src_subnet;
	protected String dst_subnet;
	
	public long getSys_uptime() {
		return sys_uptime;
	}

	public void setSys_uptime(long sys_uptime) {
		this.sys_uptime = sys_uptime;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	public String getSrcaddr() {
		return srcaddr;
	}

	public void setSrcaddr(String srcaddr) {
		this.srcaddr = srcaddr;
	}

	public String getDstaddr() {
		return dstaddr;
	}

	public void setDstaddr(String dstaddr) {
		this.dstaddr = dstaddr;
	}

	public int getSrc_as() {
		return src_as;
	}

	public void setSrc_as(int src_as) {
		this.src_as = src_as;
	}

	public int getDst_as() {
		return dst_as;
	}

	public void setDst_as(int dst_as) {
		this.dst_as = dst_as;
	}

	public int getSrcport() {
		return srcport;
	}

	public void setSrcport(int srcport) {
		this.srcport = srcport;
	}

	public int getDstport() {
		return dstport;
	}

	public void setDstport(int dstport) {
		this.dstport = dstport;
	}

	public long getdPkts() {
		return dPkts;
	}

	public void setdPkts(long dPkts) {
		this.dPkts = dPkts;
	}

	public String getNexthop() {
		return nexthop;
	}

	public void setNexthop(String nexthop) {
		this.nexthop = nexthop;
	}

	public int getInput() {
		return input;
	}

	public void setInput(int input) {
		this.input = input;
	}

	public int getOutput() {
		return output;
	}

	public void setOutput(int output) {
		this.output = output;
	}

	public int getPad1() {
		return pad1;
	}

	public void setPad1(int pad1) {
		this.pad1 = pad1;
	}

	public long getdOctets() {
		return dOctets;
	}

	public void setdOctets(long dOctets) {
		this.dOctets = dOctets;
	}

	public int getSrc_mask() {
		return src_mask;
	}

	public void setSrc_mask(int src_mask) {
		this.src_mask = src_mask;
	}

	public int getDst_mask() {
		return dst_mask;
	}

	public void setDst_mask(int dst_mask) {
		this.dst_mask = dst_mask;
	}

	public int getTcp_flags() {
		return tcp_flags;
	}

	public void setTcp_flags(int tcp_flags) {
		this.tcp_flags = tcp_flags;
	}

	public int getProt() {
		return prot;
	}

	public void setProt(int prot) {
		this.prot = prot;
	}

	public int getTos() {
		return tos;
	}

	public void setTos(int tos) {
		this.tos = tos;
	}

	public int getPad2() {
		return pad2;
	}

	public void setPad2(int pad2) {
		this.pad2 = pad2;
	}

	public long getFirst() {
		return first;
	}

	public void setFirst(long first) {
		this.first = first;
	}

	public long getLast() {
		return last;
	}

	public void setLast(long last) {
		this.last = last;
	}

	public void setOrderby(Buffer orderby) {
		this.orderby = orderby;
	}

	public static org.apache.hadoop.record.meta.RecordTypeInfo getTypeInfo() {
		    return _rio_recTypeInfo;
	}

	public static void setTypeFilter(org.apache.hadoop.record.meta.RecordTypeInfo rti) {
	  if (null == rti) return;
	  _rio_rtiFilter = rti;
	  _rio_rtiFilterFields = null;
	}

	protected static void setupRtiFields()
	{
	  if (null == _rio_rtiFilter) return;
	  // we may already have done this
	  if (null != _rio_rtiFilterFields) return;
	  int _rio_i, _rio_j;
	  _rio_rtiFilterFields = new int [_rio_rtiFilter.getFieldTypeInfos().size()];
	  for (_rio_i=0; _rio_i<_rio_rtiFilterFields.length; _rio_i++) {
	    _rio_rtiFilterFields[_rio_i] = 0;
	  }
	  java.util.Iterator<org.apache.hadoop.record.meta.FieldTypeInfo> _rio_itFilter = _rio_rtiFilter.getFieldTypeInfos().iterator();
	  _rio_i=0;
	  while (_rio_itFilter.hasNext()) {
	    org.apache.hadoop.record.meta.FieldTypeInfo _rio_tInfoFilter = _rio_itFilter.next();
	    java.util.Iterator<org.apache.hadoop.record.meta.FieldTypeInfo> _rio_it = _rio_recTypeInfo.getFieldTypeInfos().iterator();
	    _rio_j=1;
	    while (_rio_it.hasNext()) {
	      org.apache.hadoop.record.meta.FieldTypeInfo _rio_tInfo = _rio_it.next();
	      if (_rio_tInfo.equals(_rio_tInfoFilter)) {
	        _rio_rtiFilterFields[_rio_i] = _rio_j;
	        break;
	      }
	      _rio_j++;
	    }
	    _rio_i++;
	  }
	}


	protected void deserializeWithoutFilter(final org.apache.hadoop.record.RecordInput _rio_a, final String _rio_tag)
		throws java.io.IOException {
		
		// TODO Auto-generated method stub
	    _rio_a.startRecord(_rio_tag); 

	    this.sys_uptime = _rio_a.readLong("sys_uptime");
	    this.timestamp = _rio_a.readLong("timestamp");	
	    this.srcaddr = _rio_a.readString("srcaddr");
	    this.dstaddr = _rio_a.readString("dstaddr");
	    this.nexthop = _rio_a.readString("nexthop");
	    this.input = _rio_a.readInt("input");
	    this.output = _rio_a.readInt("output");
	    this.dPkts = _rio_a.readLong("dPkts");
	    this.dOctets = _rio_a.readLong("dOctets");
	    this.first = _rio_a.readLong("first");
	    this.last = _rio_a.readLong("last");	    
	    this.srcport = _rio_a.readInt("srcport");
	    this.dstport = _rio_a.readInt("dstport");
	    this.pad1 = _rio_a.readInt("pad1");
	    this.tcp_flags = _rio_a.readInt("tcp_flags");
	    this.prot = _rio_a.readInt("prot");
	    this.tos = _rio_a.readInt("tos");
	    this.src_as = _rio_a.readInt("src_as");
	    this.dst_as = _rio_a.readInt("dst_as");
	    this.src_mask = _rio_a.readInt("src_mask");
	    this.dst_mask = _rio_a.readInt("dst_mask");
	    this.pad2 = _rio_a.readInt("pad2");

	    this.orderby = _rio_a.readBuffer("orderby");
	    
	    _rio_a.endRecord(_rio_tag);		
	}
	
	public void deserialize(final org.apache.hadoop.record.RecordInput _rio_a, final String _rio_tag)
	throws java.io.IOException {
	  if (null == _rio_rtiFilter) {
	    deserializeWithoutFilter(_rio_a, _rio_tag);
	    return;
	  }
	  // if we're here, we need to read based on version info
	  _rio_a.startRecord(_rio_tag);
	  setupRtiFields();
	  for (int _rio_i=0; _rio_i<_rio_rtiFilter.getFieldTypeInfos().size(); _rio_i++) {

		if (1 == _rio_rtiFilterFields[_rio_i]) { sys_uptime = _rio_a.readLong("sys_uptime");}
		else if (2 == _rio_rtiFilterFields[_rio_i]) { timestamp = _rio_a.readLong("timestamp");}
		else if (3 == _rio_rtiFilterFields[_rio_i]) { srcaddr = _rio_a.readString("srcaddr");}
		else if (4 == _rio_rtiFilterFields[_rio_i]) { dstaddr = _rio_a.readString("dstaddr");}
		else if (5 == _rio_rtiFilterFields[_rio_i]) { nexthop = _rio_a.readString("nexthop");}
		else if (6 == _rio_rtiFilterFields[_rio_i]) { input = _rio_a.readInt("input");}
		else if (7 == _rio_rtiFilterFields[_rio_i]) { output = _rio_a.readInt("output");}
		else if (8 == _rio_rtiFilterFields[_rio_i]) { dPkts = _rio_a.readLong("dPkts");}
		else if (9 == _rio_rtiFilterFields[_rio_i]) { dOctets = _rio_a.readLong("dOctets");}	
		else if (10 == _rio_rtiFilterFields[_rio_i]) { first = _rio_a.readLong("first");}
		else if (11 == _rio_rtiFilterFields[_rio_i]) { last = _rio_a.readLong("last");}
		else if (12 == _rio_rtiFilterFields[_rio_i]) { srcport = _rio_a.readInt("srcport");}
		else if (13 == _rio_rtiFilterFields[_rio_i]) { dstport = _rio_a.readInt("dstport");}
		else if (14 == _rio_rtiFilterFields[_rio_i]) { pad1 = _rio_a.readInt("pad1");}
		else if (15 == _rio_rtiFilterFields[_rio_i]) { tcp_flags = _rio_a.readInt("tcp_flags");}
		else if (16== _rio_rtiFilterFields[_rio_i]) { prot = _rio_a.readInt("prot");}
		else if (17 == _rio_rtiFilterFields[_rio_i]) { tos = _rio_a.readInt("tos");}
		else if (18 == _rio_rtiFilterFields[_rio_i]) { src_as = _rio_a.readInt("src_as");}
		else if (19 == _rio_rtiFilterFields[_rio_i]) { dst_as = _rio_a.readInt("dst_as");}
		else if (20 == _rio_rtiFilterFields[_rio_i]) { src_mask = _rio_a.readInt("src_mask");}
		else if (21 == _rio_rtiFilterFields[_rio_i]) { dst_mask = _rio_a.readInt("dst_mask");}
		else if (22 == _rio_rtiFilterFields[_rio_i]) { pad2 = _rio_a.readInt("pad2");}
		else if (23 == _rio_rtiFilterFields[_rio_i]) { orderby = _rio_a.readBuffer("orderby");}
		else {
	      java.util.ArrayList<org.apache.hadoop.record.meta.FieldTypeInfo> typeInfos = (java.util.ArrayList<org.apache.hadoop.record.meta.FieldTypeInfo>)(_rio_rtiFilter.getFieldTypeInfos());
	      org.apache.hadoop.record.meta.Utils.skip(_rio_a, typeInfos.get(_rio_i).getFieldID(), typeInfos.get(_rio_i).getTypeID());
	    }
	  }
	  _rio_a.endRecord(_rio_tag);
	}	
	
	@Override
	public void serialize(final org.apache.hadoop.record.RecordOutput _rio_a, final String _rio_tag) throws IOException {
		// TODO Auto-generated method stub

	    _rio_a.startRecord(this,_rio_tag);
	    
		_rio_a.writeLong(sys_uptime, "sys_uptime");
		_rio_a.writeLong(timestamp, "timestamp");
		_rio_a.writeString(srcaddr, "srcaddr");
		_rio_a.writeString(dstaddr, "dstaddr");
		_rio_a.writeString(nexthop, "nexthop");
		_rio_a.writeInt(input, "input");
		_rio_a.writeInt(output, "output");
		_rio_a.writeLong(dPkts, "dPkts");		
		_rio_a.writeLong(dOctets, "dOctets");
		_rio_a.writeLong(first, "first");
		_rio_a.writeLong(last, "last");	
		_rio_a.writeInt(srcport, "srcport");
		_rio_a.writeInt(dstport, "dstport");
		_rio_a.writeInt(pad1, "pad1");
		_rio_a.writeInt(tcp_flags, "tcp_flags");
		_rio_a.writeInt(prot, "prot");
		_rio_a.writeInt(tos, "tos");
		_rio_a.writeInt(src_as, "src_as");
		_rio_a.writeInt(dst_as, "dst_as");
		_rio_a.writeInt(src_mask, "src_mask");
		_rio_a.writeInt(dst_mask, "dst_mask");
		_rio_a.writeInt(pad2, "pad2");		
		_rio_a.writeBuffer(orderby, "orderby");	
		
	    _rio_a.endRecord(this,_rio_tag);
	}
	
	public EZBytes getEb() {
		return eb;
	}

	public void setEb(EZBytes eb) {
		this.eb = eb;
	}

	@Override
	public boolean equals(Object obj) {
		// TODO Auto-generated method stub
		return super.equals(obj);
	}
	

	/**
	 * 
	 * @author dnlab
	 *
	 */
	public FlowWritable clone(FlowWritable fw){
		
		fw.sys_uptime = sys_uptime;
		fw.timestamp = timestamp;
		fw.srcaddr = srcaddr;
		fw.dstaddr = dstaddr;
		fw.src_as = src_as;
		fw.dst_as = dst_as;
		fw.srcport = srcport;
		fw.dstport = dstport;
		fw.dPkts = dPkts;
		fw.input = input;
		fw.output = output;
		fw.pad1 = pad1;
		fw.dOctets = dOctets;
		fw.src_mask = src_mask;
		fw.dst_mask = dst_mask;
		fw.tcp_flags = tcp_flags;
		fw.prot = prot;
		fw.tos = tos;
		fw.pad2 = pad2;
		fw.first = first;
		fw.last = last;
		fw.orderby = orderby;		
		return fw;
	}  

	public boolean parse(long sys_uptime, long timestamp, byte[] pdata){
		
		byte[] orderby = new byte[13];
		
		eb = new EZBytes(pdata.length);
		eb.PutBytes(pdata, 0, pdata.length);
		
		// C2S key ==> protocol | srcIP | dstIP | sPort |dPort
		System.arraycopy(pdata, NetFlow.SRCADDR[0], orderby, 0, NetFlow.SRCADDR[1]);	
		System.arraycopy(pdata, NetFlow.SRCPORT[0], orderby, 8, NetFlow.SRCPORT[1]);	
		System.arraycopy(pdata, NetFlow.PROT[0], orderby, 12, NetFlow.PROT[1]);
		this.setOrderby(orderby);
		
		try {
			this.sys_uptime = sys_uptime;
			this.timestamp = timestamp;
			this.srcaddr = InetAddress.getByAddress(eb.GetBytes(NetFlow.SRCADDR[0],NetFlow.SRCADDR[1])).toString();
			this.dstaddr = InetAddress.getByAddress(eb.GetBytes(NetFlow.DSTADDR[0],NetFlow.DSTADDR[1])).toString();
			this.src_as = Bytes.toInt(eb.GetBytes(NetFlow.SRC_AS[0],NetFlow.SRC_AS[1]));
			this.dst_as = Bytes.toInt(eb.GetBytes(NetFlow.DST_AS[0],NetFlow.DST_AS[1]));
			this.nexthop = InetAddress.getByAddress(eb.GetBytes(NetFlow.NEXTHOP[0],NetFlow.NEXTHOP[1])).toString();
			this.input = Bytes.toInt(eb.GetBytes(NetFlow.INPUT[0],NetFlow.INPUT[1]));
			this.output = Bytes.toInt(eb.GetBytes(NetFlow.OUTPUT[0],NetFlow.OUTPUT[1]));
			this.dPkts = Bytes.toLong(eb.GetBytes(NetFlow.DPKTS[0],NetFlow.DPKTS[1]));
			this.dOctets = Bytes.toLong(eb.GetBytes(NetFlow.DOCTETS[0],NetFlow.DOCTETS[1]));		
			this.first = Bytes.toLong(eb.GetBytes(NetFlow.FIRST[0],NetFlow.FIRST[1]));
			this.last = Bytes.toLong(eb.GetBytes(NetFlow.LAST[0],NetFlow.LAST[1]));				
			this.srcport = Bytes.toInt(eb.GetBytes(NetFlow.SRCPORT[0], NetFlow.SRCPORT[1]));
			this.dstport = Bytes.toInt(eb.GetBytes(NetFlow.DSTPORT[0], NetFlow.DSTPORT[1]));
			
			this.pad1 = Bytes.toInt(eb.GetBytes(NetFlow.PAD1[0],NetFlow.PAD1[1]));
			this.tcp_flags = Bytes.toInt(eb.GetBytes(NetFlow.TCP_FLAGS[0],NetFlow.TCP_FLAGS[1]));
			this.prot = Bytes.toInt(eb.GetBytes(NetFlow.PROT[0],NetFlow.PROT[1]));
			this.tos = Bytes.toInt(eb.GetBytes(NetFlow.TOS[0],NetFlow.TOS[1]));
			this.src_mask = Bytes.toInt(eb.GetByte(NetFlow.SRC_MASK[0]));
			this.dst_mask = Bytes.toInt(eb.GetByte(NetFlow.DST_MASK[0]));
			// modified mask bit --> subnet addr
			this.src_subnet = InetAddress.getByAddress(BinaryUtils.uIntToBytes(
					Bytes.toLong(eb.GetBytes(NetFlow.SRCADDR[0], NetFlow.SRCADDR[1])) & (0xffffffffL << src_mask))).toString();
			this.dst_subnet = InetAddress.getByAddress(BinaryUtils.uIntToBytes(
					Bytes.toLong(eb.GetBytes(NetFlow.DSTADDR[0], NetFlow.DSTADDR[1])) & (0xffffffffL << dst_mask))).toString();
			
			this.pad2 = Bytes.toInt(eb.GetBytes(NetFlow.PAD2[0], NetFlow.PAD2[1]));
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return true;	
	}

	public String getSrc_subnet() {
		return src_subnet;
	}

	public void setSrc_subnet(String src_subnet) {
		this.src_subnet = src_subnet;
	}

	public String getDst_subnet() {
		return dst_subnet;
	}

	public void setDst_subnet(String dst_subnet) {
		this.dst_subnet = dst_subnet;
	}

	@Override
	public int compareTo(Object obj) throws ClassCastException {
		// TODO Auto-generated method stub
		
		FlowWritable other = (FlowWritable)obj;
		
		int cmp = this.orderby.compareTo(other.orderby);
		if (cmp != 0) {
			return cmp;
		}
		return this.first>other.first?1:this.first==other.first?0:-1;
	}

	public Buffer getOrderby() {
		return orderby;
	}
	
	public void setOrderby(byte[] orderby) {
		this.orderby.setCapacity(orderby.length);
		this.orderby.set(orderby);
	}
	
	public FlowWritable() {
		super();
		this.srcaddr = new String();
		this.dstaddr = new String();
		this.nexthop = new String();
		this.orderby = new Buffer();
	}
}