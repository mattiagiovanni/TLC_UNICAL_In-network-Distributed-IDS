#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

#define MAX_REGISTER_ENTRIES 6144
#define PACKET_THRESHOLD 1000
#define FLOW_TIMEOUT 15000000 /*15 seconds: this timer is used because, since registers are limited
			       this timeout permits to erase the old values which have not been
			       seen since some time*/
			       
#define PACKET_THR 40
#define BULK_THR  1000 //bytes

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}


struct metadata {
    
    bit<32> register_index;
    bit<32> register_index_2; //for forwarding operations
    bit<32> register_index_inverse;

    bit<1> direction;
    bit<1> is_first;

    bit<32> src_ip;
    bit<32> dst_ip;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8>  protocol;
    
    bit<32> time_first_pkt;
    bit<32> time_last_pkt;
    bit<32> flow_duration;
    bit<16> bytes; //this is used to store the bytes total count
    bit<16> flow_byts_s;
    bit<8> packets; //this is used track the total amount of the packets, in order to evaluate the packet rate at the end
    
    bit<8> flow_pkts_s;
    bit<8> fwd_pkts_s;
    bit<8> bwd_pkts_s;
     
    bit<8> tot_fwd_pkts;
    bit<8> tot_bwd_pkts;
    
    bit<3> fwd_psh_flags;
    bit<3> bwd_psh_flags;
    bit<3> fwd_urg_flags;
    bit<3> bwd_urg_flags;
    bit<3> fin_flag_cnt;
    bit<3> syn_flag_cnt;
    bit<3> rst_flag_cnt;
    bit<3> psh_flag_cnt;
    bit<3> ack_flag_cnt;
    bit<3> urg_flag_cnt;
    bit<3> ece_flag_cnt;
    
    
    bit<16> totlen_fwd_pkts;
    bit<16> totlen_bwd_pkts;
    bit<16> totLen_pkts;   //this meta value is used for evaluating the total length mean
    bit<16> fwd_pkt_len_max;
    bit<16> fwd_pkt_len_min;
    bit<16> fwd_pkt_len_mean;
    bit<16> bwd_pkt_len_max;
    bit<16> bwd_pkt_len_min;
    bit<16> bwd_pkt_len_mean;
    bit<16> pkt_len_max;
    bit<16> pkt_len_min;
    bit<16> pkt_len_mean;
    bit<16> fwd_header_len;
    bit<16> bwd_header_len;
    bit<16> fwd_seg_size_min;
    bit<32> fwd_act_data_pkts;
    
    bit<32> iat;   // this is used to store the iat, so the mean can be evaluated 
    bit<32> flow_iat_mean;
    bit<32> flow_iat_max;
    bit<32> flow_iat_min;
    
    bit<32> fwd_iat;
    bit<32> fwd_iat_tot;
    bit<32> fwd_iat_mean;
    bit<32> fwd_iat_max;
    bit<32> fwd_iat_min;
    
    bit<32> bwd_iat;
    bit<32> bwd_iat_tot;
    bit<32> bwd_iat_mean;
    bit<32> bwd_iat_max;
    bit<32> bwd_iat_min;
    
    
    
    bit<16> init_fwd_win_byts;
    bit<16> init_bwd_win_byts;
    
    bit<32> active_vals;
    bit<32> active_mean;
    bit<32> active_max;
    bit<32> active_min;
    
    bit<32> idle_vals;
    bit<32> idle_mean;
    bit<32> idle_max;
    bit<32> idle_min; 
    
    
    bit<16> fwd_byts_b;
    bit<8>  fwd_b_pkts;
    
    //fwd average bytes
    bit<16> fwd_byts_b_tot;
    bit<16> fwd_byts_b_avg;
    
    
    //fwd bytes rate average
    bit<16> fwd_rate_b;
    bit<16> fwd_rate_b_tot; 
    bit<16> fwd_blk_rate_avg;
    
    //fwd packets average
    bit<8> fwd_pkts_b_tot;
    bit<8> fwd_pkts_b_avg;
    
    
    
    bit<16> bwd_byts_b;
    bit<8>  bwd_b_pkts;
    
    //bwd bytes average
    bit<16> bwd_byts_b_tot;
    bit<16> bwd_byts_b_avg;
    
    //bwd bytes rate average
    bit<16> bwd_rate_b;
    bit<16> bwd_rate_b_tot;
    bit<16> bwd_blk_rate_avg; 
    
    //bwd packets average
    bit<8> bwd_pkts_b_tot;
    bit<8> bwd_pkts_b_avg;      
    
	
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t       tcp;
    udp_t	udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

   // parse different types of packets ARP, ICMP etc.
   state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
	    17: parse_udp;
            default: accept;
    }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}




/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    
    
    //the following are the regsiters used to read and write the data written inside, in order to better manage the features
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_src_ip;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_dst_ip;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_src_port;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_dst_port;
    register<bit<8>>(MAX_REGISTER_ENTRIES)  reg_protocol;
    
    //regusters for the lifetime of the flow and the rates (flow and bytes rate)
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_time_first_pkt;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_time_last_pkt;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow_duration;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bytes;
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_packets;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_flow_byts_s;
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_flow_pkts_s;
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_fwd_pkts_s;
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_bwd_pkts_s;
    
    //registers to count the total amount of packets in forwarding and backwarding directions
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_tot_fwd_pkts;
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_tot_bwd_pkts;
    
    //the following registers allow to store the packets whose content inglobes the activation of the flags
    register<bit<3>>(MAX_REGISTER_ENTRIES) reg_fwd_psh_flags;
    register<bit<3>>(MAX_REGISTER_ENTRIES) reg_bwd_psh_flags;
    register<bit<3>>(MAX_REGISTER_ENTRIES) reg_fwd_urg_flags;
    register<bit<3>>(MAX_REGISTER_ENTRIES) reg_bwd_urg_flags;
    register<bit<3>>(MAX_REGISTER_ENTRIES) reg_fin_flag_cnt;
    register<bit<3>>(MAX_REGISTER_ENTRIES) reg_syn_flag_cnt;
    register<bit<3>>(MAX_REGISTER_ENTRIES) reg_rst_flag_cnt;
    register<bit<3>>(MAX_REGISTER_ENTRIES) reg_psh_flag_cnt;
    register<bit<3>>(MAX_REGISTER_ENTRIES) reg_ack_flag_cnt;
    register<bit<3>>(MAX_REGISTER_ENTRIES) reg_urg_flag_cnt;
    register<bit<3>>(MAX_REGISTER_ENTRIES) reg_ece_flag_cnt;
    
    // the following registers are for the length, its max and minimum values, the mean
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_totlen_fwd_pkts;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_totlen_bwd_pkts;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_totLen_pkts;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_pkt_len_max;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_pkt_len_min;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_pkt_len_mean;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bwd_pkt_len_max;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bwd_pkt_len_min;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bwd_pkt_len_mean;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_pkt_len_max;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_pkt_len_min;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_pkt_len_mean;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_header_len;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bwd_header_len;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_seg_size_min;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_act_data_pkts;
    
    //the following store features which concern the inter-arrival time (interval time between two packets in a flow)
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_iat;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow_iat_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow_iat_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow_iat_min;
    
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_iat;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_iat_tot;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_iat_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_iat_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_iat_min;
    
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_iat;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_iat_tot;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_iat_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_iat_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_iat_min;
    
    
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_init_fwd_win_byts;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_init_bwd_win_byts;
    
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_active_vals;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_active_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_active_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_active_min;
    
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_idle_vals;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_idle_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_idle_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_idle_min;
    
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_byts_b;
    register<bit<8>>(MAX_REGISTER_ENTRIES)  reg_fwd_b_pkts;
    
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_byts_b_tot;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_byts_b_avg;
    
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_rate_b;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_rate_b_tot;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_blk_rate_avg;
    
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_fwd_pkts_b_tot;
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_fwd_pkts_b_avg;
    
    
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bwd_byts_b;
    register<bit<8>>(MAX_REGISTER_ENTRIES)  reg_bwd_b_pkts;
    
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bwd_byts_b_tot;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bwd_byts_b_avg;
    
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bwd_rate_b;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bwd_rate_b_tot;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bwd_blk_rate_avg;
    
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_bwd_pkts_b_tot;
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_bwd_pkts_b_avg; 
    
    
    
    
    action init_register() {
	//this action is in charge of intialising the registers to 0
	reg_src_ip.write(meta.register_index, 0);
	reg_dst_ip.write(meta.register_index, 0);
	reg_src_port.write(meta.register_index, 0);
	reg_dst_port.write(meta.register_index, 0);
	reg_protocol.write(meta.register_index, 0);
    
        reg_time_first_pkt.write(meta.register_index, 0);
        reg_flow_duration.write(meta.register_index, 0);
        
        reg_bytes.write(meta.register_index, 0);
        
        reg_flow_byts_s.write(meta.register_index, 0);
        
        reg_packets.write(meta.register_index, 0);
        
        reg_flow_pkts_s.write(meta.register_index, 0);
        
        reg_fwd_pkts_s.write(meta.register_index_2, 0);
        reg_bwd_pkts_s.write(meta.register_index_inverse, 0);
        
        reg_tot_fwd_pkts.write(meta.register_index_2, 0);
        reg_tot_bwd_pkts.write(meta.register_index_inverse, 0);
        
        reg_fwd_psh_flags.write(meta.register_index_2, 0);
        reg_bwd_psh_flags.write(meta.register_index_inverse, 0);
        reg_fwd_urg_flags.write(meta.register_index_2, 0);
        reg_bwd_urg_flags.write(meta.register_index_inverse, 0);
        
        reg_fin_flag_cnt.write(meta.register_index, 0);
        reg_syn_flag_cnt.write(meta.register_index, 0);
        reg_rst_flag_cnt.write(meta.register_index, 0);
        reg_psh_flag_cnt.write(meta.register_index, 0);
        reg_ack_flag_cnt.write(meta.register_index, 0);
        reg_urg_flag_cnt.write(meta.register_index, 0);
        reg_ece_flag_cnt.write(meta.register_index, 0);
        
        reg_totlen_fwd_pkts.write(meta.register_index_2, 0);
        reg_totlen_bwd_pkts.write(meta.register_index_inverse, 0);
        reg_totLen_pkts.write(meta.register_index, 0);
        
        reg_fwd_pkt_len_max.write(meta.register_index_2, 0);
        reg_fwd_pkt_len_min.write(meta.register_index_2, 0);
        reg_fwd_pkt_len_mean.write(meta.register_index_2, 0);
        
        reg_bwd_pkt_len_max.write(meta.register_index_inverse, 0);
        reg_bwd_pkt_len_min.write(meta.register_index_inverse, 0);
        reg_bwd_pkt_len_mean.write(meta.register_index_inverse, 0);
        
        reg_pkt_len_max.write(meta.register_index, 0);
        reg_pkt_len_min.write(meta.register_index, 0);
        reg_pkt_len_mean.write(meta.register_index, 0);
        
        reg_fwd_header_len.write(meta.register_index_2, 0);
        reg_bwd_header_len.write(meta.register_index_inverse, 0);
        
        reg_fwd_seg_size_min.write(meta.register_index_2, 0);
        
        reg_fwd_act_data_pkts.write(meta.register_index_2, 0);
        
        reg_iat.write(meta.register_index, 0);
        reg_flow_iat_mean.write(meta.register_index, 0);
        reg_flow_iat_max.write(meta.register_index, 0);
        reg_flow_iat_min.write(meta.register_index, 0);
        
        reg_fwd_iat.write(meta.register_index_2, 0);
        reg_fwd_iat_tot.write(meta.register_index_2, 0);
        reg_fwd_iat_mean.write(meta.register_index_2, 0);
        reg_fwd_iat_max.write(meta.register_index_2, 0);
        reg_fwd_iat_min.write(meta.register_index_2, 0);
        
        reg_bwd_iat.write(meta.register_index_inverse, 0);
        reg_bwd_iat_tot.write(meta.register_index_inverse, 0);
        reg_bwd_iat_mean.write(meta.register_index_inverse, 0);
        reg_bwd_iat_max.write(meta.register_index_inverse, 0);
        reg_bwd_iat_min.write(meta.register_index_inverse, 0);
        
        
        reg_init_fwd_win_byts.write(meta.register_index_2, 0);
        reg_init_bwd_win_byts.write(meta.register_index_inverse, 0);
        
        reg_active_vals.write(meta.register_index, 0);
        reg_active_mean.write(meta.register_index, 0);
        reg_active_max.write(meta.register_index, 0);
        reg_active_min.write(meta.register_index, 0);
        
        reg_idle_vals.write(meta.register_index, 0);
        reg_idle_mean.write(meta.register_index, 0);
        reg_idle_max.write(meta.register_index, 0);
        reg_idle_min.write(meta.register_index, 0);
        
        reg_fwd_byts_b.write(meta.register_index_2, 0);
        reg_fwd_b_pkts.write(meta.register_index_2, 0);
        
        reg_fwd_byts_b_tot.write(meta.register_index_2, 0);
        reg_fwd_byts_b_avg.write(meta.register_index_2, 0);
        
        reg_fwd_rate_b.write(meta.register_index_2, 0);
        reg_fwd_rate_b_tot.write(meta.register_index_2, 0);
        reg_fwd_blk_rate_avg.write(meta.register_index_2, 0);
        
        reg_fwd_pkts_b_tot.write(meta.register_index_2, 0);
        reg_fwd_pkts_b_avg.write(meta.register_index_2, 0);
        
    
        reg_bwd_byts_b.write(meta.register_index_inverse, 0);
        reg_bwd_b_pkts.write(meta.register_index_inverse, 0);
        
        reg_bwd_byts_b_tot.write(meta.register_index_inverse, 0);
    	reg_bwd_byts_b_avg.write(meta.register_index_inverse, 0);
    	
    	reg_bwd_rate_b.write(meta.register_index_inverse, 0);
    	reg_bwd_rate_b_tot.write(meta.register_index_inverse, 0);
    	reg_bwd_blk_rate_avg.write(meta.register_index_inverse, 0);
    	
    	reg_bwd_pkts_b_tot.write(meta.register_index_inverse, 0);
    	reg_bwd_pkts_b_avg.write(meta.register_index_inverse, 0); 
    }


    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    
    
     
     action get_register_index_tcp() {
    //Get register position through the 5-tuple
		hash(meta.register_index, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
	                        hdr.ipv4.dstAddr,
				 hdr.tcp.srcPort,
	                        hdr.tcp.dstPort,
				 hdr.ipv4.protocol},
				 (bit<32>)MAX_REGISTER_ENTRIES);

		hash(meta.register_index_2, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr,
                                hdr.ipv4.dstAddr,
                                hdr.tcp.srcPort,
                                hdr.tcp.dstPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);
	}

    action get_register_index_udp() {
 	        hash(meta.register_index, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
                                hdr.ipv4.dstAddr,
                                hdr.udp.srcPort,
                                hdr.udp.dstPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);

                hash(meta.register_index_2, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr,
                                hdr.ipv4.dstAddr,
                                hdr.udp.srcPort,
                                hdr.udp.dstPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);
	}

    action get_register_index_inverse_tcp() {
    //Get register position for the same flow in another directon
    // just inverse the src and dst
                hash(meta.register_index_inverse, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.dstAddr,
                                hdr.ipv4.srcAddr,
                                hdr.tcp.dstPort,
                                hdr.tcp.srcPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);
    }
                                

    action get_register_index_inverse_udp() {
                hash(meta.register_index_inverse, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.dstAddr,
                                hdr.ipv4.srcAddr,
                                hdr.udp.dstPort,
                                hdr.udp.srcPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);

    }
     

    action drop() {
        mark_to_drop(standard_metadata);
    }


    action first_features() {
    /*this action reads and write in the relative registers, the source and destination IP addresses, as well as the ports and the protocol
    and it will be the first one to be triggered in the apply section*/
    	reg_src_ip.read(meta.src_ip, meta.register_index);
    	//meta.src_ip = hdr.ipv4.srcAddr;
    	reg_src_ip.write(meta.register_index, hdr.ipv4.srcAddr);
    	
    	
    	reg_dst_ip.read(meta.dst_ip, meta.register_index);
    	//meta.dst_ip = hdr.ipv4.dstAddr;
    	reg_dst_ip.write(meta.register_index, hdr.ipv4.dstAddr);
    	
    	
    	reg_src_port.read(meta.src_port, meta.register_index);
    	//meta.src_port = hdr.tcp.srcPort;
    	reg_src_port.write(meta.register_index, hdr.tcp.srcPort);
    	
    	
    	reg_dst_port.read(meta.dst_port, meta.register_index);
    	//meta.hdr_dst_port = hdr.tcp.dstPort;
    	reg_dst_port.write(meta.register_index, hdr.tcp.srcPort);
    	
    	
    	reg_protocol.read(meta.protocol, meta.register_index);
    	//meta.proto = hdr.ipv4.protocol;
    	reg_protocol.write(meta.register_index, hdr.ipv4.protocol);
    }
    


    action calc_dur() {
    /*this action evaluates the lifetime of the flow*/
        reg_time_first_pkt.read(meta.time_first_pkt, meta.register_index);   
            
	//reg_dur.read(meta.dur, meta.register_index);
	meta.flow_duration = (bit<32>)standard_metadata.ingress_global_timestamp - meta.time_first_pkt;
	reg_flow_duration.write(meta.register_index, meta.flow_duration);
    }
    
    
    
    
    action flow_bytes_tot() {
    /*this action performs the total amount of bytes sent, by adding to the meta.bytes
    the standard_metadata.packet_length which is the packet length*/
    	reg_bytes.read(meta.bytes, meta.register_index);
    	meta.bytes = (meta.bytes + hdr.ipv4.totalLen) << 8;  //the bitshifting to 8 allows to convert the value from bits to bytes
    	reg_bytes.write(meta.register_index, meta.bytes);
    }
    
    
    
    
    action fwd_flow_bytes_tot() {
    // this is for counting the number of bytes for the amount building up the forwarding bulk
    	reg_fwd_byts_b.read(meta.fwd_byts_b, meta.register_index_2);
    	meta.fwd_byts_b = (meta.fwd_byts_b + hdr.ipv4.totalLen) << 8;  
    	reg_fwd_byts_b.write(meta.register_index_2, meta.fwd_byts_b);
    }
    
    
    
    action bwd_flow_bytes_tot() {
    // this is for counting the number of bytes for the amount building up the backwarding bulk
    	reg_bwd_byts_b.read(meta.bwd_byts_b, meta.register_index_inverse);
    	meta.bwd_byts_b = (meta.bwd_byts_b + hdr.ipv4.totalLen) << 8;  
    	reg_bwd_byts_b.write(meta.register_index_inverse, meta.bwd_byts_b);
    }     
      
    
    
        
    
    action flow_pkts_tot () {
    /*this register could be seen as a counter because, everytime a packet is detected,
    the counter and so the register, is updated*/
    	reg_packets.read(meta.packets, meta.register_index);
    	meta.packets = meta.packets + 1;
    	reg_packets.write(meta.register_index, meta.packets);
    }
    


    action fwd_b_flow_pkts_tot () {
    /*this register could be seen as a counter because, everytime a packet is detected,
    the counter and so the register, is updated*/
    	reg_fwd_b_pkts.read(meta.fwd_b_pkts, meta.register_index_2);
    	meta.fwd_b_pkts = meta.fwd_b_pkts + 1;
    	reg_fwd_b_pkts.write(meta.register_index_2, meta.fwd_b_pkts);
    }
    
    
    action bwd_b_flow_pkts_tot () {
    /*this register could be seen as a counter because, everytime a packet is detected,
    the counter and so the register, is updated*/
    	reg_bwd_b_pkts.read(meta.bwd_b_pkts, meta.register_index_inverse);
    	meta.bwd_b_pkts = meta.bwd_b_pkts + 1;
    	reg_bwd_b_pkts.write(meta.register_index_inverse, meta.bwd_b_pkts);
    }   
    
    
    
    
    action flow_pkts_rate() {	
    //in this action happens something a little tricky to handle: the evaluation of the flow and the packets rate
    
    	reg_flow_duration.read(meta.flow_duration, meta.register_index);
    	reg_bytes.read(meta.bytes, meta.register_index);
    	reg_packets.read(meta.packets, meta.register_index);
    //the dur, bytes and packets registers are red, so that it could be possibile to access to the content of them
    	
    	reg_flow_byts_s.read(meta.flow_byts_s, meta.register_index);
    	reg_flow_pkts_s.read(meta.flow_pkts_s, meta.register_index);
    	
    	meta.flow_byts_s = meta.bytes << (bit<8>)meta.flow_duration;
    	meta.flow_pkts_s = meta.packets << (bit<8>)meta.flow_duration;
    /*once the registers which will englobe the rates are red, it is possible now to work on the relative metadata,
    as it is possible to see, the rates are calculated through the bit-shifting because the division is not supported in P4, because of
    the floating point operations; full accuracy won't be achieved, but it's better than nothing*/
    	
    	reg_flow_byts_s.write(meta.register_index, meta.flow_byts_s);  
    	reg_flow_pkts_s.write(meta.register_index, meta.flow_pkts_s); 	
    }





    action active_mean() {
    
    	reg_time_last_pkt.write(meta.register_index, (bit<32>)standard_metadata.ingress_global_timestamp);
    	reg_time_first_pkt.read(meta.time_first_pkt, meta.register_index);
    	reg_active_vals.read(meta.active_vals, meta.register_index);
    	
    	meta.active_vals = meta.time_last_pkt - meta.time_first_pkt;
    	reg_active_vals.write(meta.register_index, meta.active_vals);
    	
    	reg_active_mean.read(meta.register_index, meta.active_mean);
    	meta.active_mean = meta.active_vals << meta.packets;
    	reg_active_mean.write(meta.register_index, meta.active_mean);
        
    }


    action active_min() {
    
    	//reg_active_vals.read(meta.active_vals, meta.register_index);
	reg_active_min.read(meta.active_min, meta.register_index);
	
	meta.active_min = meta.active_vals;
	if(meta.active_vals < meta.active_min) {
		meta.active_min = meta.active_vals;
	}
	reg_active_min.write(meta.register_index, meta.active_min);
        
    }


    action active_max() {
    
    	//reg_active_vals.read(meta.active_vals, meta.register_index);
	reg_active_max.read(meta.active_max, meta.register_index);
	
	if(meta.active_vals > meta.active_max) {
		meta.active_max = meta.active_vals;
	}
	reg_active_max.write(meta.register_index, meta.active_max);
        
    }



    action idle_mean() {
    
    	reg_time_last_pkt.write(meta.register_index, (bit<32>)standard_metadata.ingress_global_timestamp);
    	reg_idle_vals.read(meta.idle_vals, meta.register_index);
    	
    	meta.idle_vals = (bit<32>)standard_metadata.ingress_global_timestamp - meta.time_last_pkt;
    	reg_idle_vals.write(meta.register_index, meta.idle_vals);
    	
    	reg_idle_mean.read(meta.register_index, meta.idle_mean);
    	meta.idle_mean = meta.idle_vals << meta.packets;
    	reg_idle_mean.write(meta.register_index, meta.idle_mean);
        
    }


    action idle_min() {
    
    	//reg_idle_vals.read(meta.idle_vals, meta.register_index);
	reg_idle_min.read(meta.idle_min, meta.register_index);
	
	meta.idle_min = meta.idle_vals;
	if(meta.idle_vals < meta.idle_min) {
		meta.idle_min = meta.idle_vals;
	}
	reg_idle_min.write(meta.register_index, meta.idle_min);
        
    }


    action idle_max() {
    
    	//reg_idle_vals.read(meta.idle_vals, meta.register_index);
	reg_idle_max.read(meta.idle_max, meta.register_index);
	
	if(meta.idle_vals > meta.idle_max) {
		meta.idle_max = meta.idle_vals;
	}
	reg_idle_max.write(meta.register_index, meta.idle_max);
        
    }



    
       
    action count_and_rate_pkts_fwd() {
    //here it happens the same pattern of before, but this time, it is about the packets in forwarding direction
    	reg_tot_fwd_pkts.read(meta.tot_fwd_pkts, meta.register_index_2);
    	meta.tot_fwd_pkts = meta.tot_fwd_pkts + 1;
    	reg_tot_fwd_pkts.write(meta.register_index_2, meta.tot_fwd_pkts);
    	
    	calc_dur();
    	reg_tot_fwd_pkts.read(meta.tot_fwd_pkts, meta.register_index_2);
    	reg_fwd_pkts_s.read(meta.fwd_pkts_s, meta.register_index_2);
    	meta.fwd_pkts_s = meta.tot_fwd_pkts << (bit<8>)meta.flow_duration;
    	reg_fwd_pkts_s.write(meta.register_index_2, meta.fwd_pkts_s);
    }
    

    
    action count_and_rate_pkts_bwd() {
    //here it happens the same pattern of before, but this time, it is about the packets in backwarding direction
    	reg_tot_bwd_pkts.read(meta.tot_bwd_pkts, meta.register_index_inverse);
    	meta.tot_bwd_pkts = meta.tot_bwd_pkts + 1;
    	reg_tot_bwd_pkts.write(meta.register_index_inverse, meta.tot_bwd_pkts);
    	
	calc_dur();
    	reg_tot_bwd_pkts.read(meta.tot_bwd_pkts, meta.register_index_inverse);
    	reg_bwd_pkts_s.read(meta.bwd_pkts_s, meta.register_index_inverse);
    	meta.bwd_pkts_s = meta.tot_bwd_pkts << (bit<8>)meta.flow_duration;
    	reg_bwd_pkts_s.write(meta.register_index_inverse, meta.bwd_pkts_s);    	
    }
    
    
    
    //the following two actions are in charge to increase the relative registers if the packet has one of the represented flags activated
    action count_fwd_flags() {
        reg_fwd_psh_flags.read(meta.fwd_psh_flags, meta.register_index_2);
    	if (hdr.tcp.psh == (bit<1>) 1) {
    		meta.fwd_psh_flags = meta.fwd_psh_flags + 1;
    	}
    	reg_fwd_psh_flags.write(meta.register_index_2, meta.fwd_psh_flags);
    	
    	
    	reg_fwd_urg_flags.read(meta.fwd_urg_flags, meta.register_index_2);
    	if (hdr.tcp.urg == (bit<1>) 1) {
    		meta.fwd_urg_flags = meta.fwd_urg_flags + 1;
    	}
    	reg_fwd_urg_flags.write(meta.register_index_2, meta.fwd_urg_flags);
    	
    }
    
    
    action count_bwd_flags() {
        reg_bwd_psh_flags.read(meta.bwd_psh_flags, meta.register_index);
    	if (hdr.tcp.psh == (bit<1>) 1) {
    		meta.bwd_psh_flags = meta.bwd_psh_flags + 1;
    	}
    	reg_bwd_psh_flags.write( meta.register_index, meta.bwd_psh_flags);
    	
    	
    	reg_bwd_urg_flags.read(meta.bwd_urg_flags, meta.register_index);
    	if (hdr.tcp.urg == (bit<1>) 1) {
    		meta.bwd_urg_flags = meta.bwd_urg_flags + 1;
    	}
    	reg_bwd_urg_flags.write( meta.register_index, meta.bwd_urg_flags);
    
    }   
    
    
    
    //the following two actions are about the total length of the forwarding and backwarding directions packets and its mean
    action calc_Length_fwd_tot_mean() {
    	reg_totlen_fwd_pkts.read(meta.totlen_fwd_pkts, meta.register_index_2);
    	meta.totlen_fwd_pkts = meta.totlen_fwd_pkts + hdr.ipv4.totalLen;//meta.tolLen_fwd_pkts + (bit<16>)standard_metadata.packet_length;
    	reg_totlen_fwd_pkts.write(meta.register_index_2, meta.totlen_fwd_pkts);
    	
    	reg_tot_fwd_pkts.read(meta.tot_fwd_pkts, meta.register_index_2);
    	//reg_totlen_fwd_pkts.read(meta.totlen_fwd_pkts, meta.register_index);
    	reg_fwd_pkt_len_mean.read(meta.fwd_pkt_len_mean, meta.register_index_2);
    	
    	meta.fwd_pkt_len_mean = meta.totlen_fwd_pkts << meta.tot_fwd_pkts;
    	
    	reg_fwd_pkt_len_mean.write( meta.register_index_2, meta.fwd_pkt_len_mean);
    }
    
    


   
    action calc_Length_bwd_tot_mean() {
    	reg_totlen_bwd_pkts.read(meta.totlen_bwd_pkts, meta.register_index_inverse);
    	meta.totlen_bwd_pkts = meta.totlen_bwd_pkts + hdr.ipv4.totalLen;//meta.totLen_bwd_pkts + (bit<16>)standard_metadata.packet_length;
    	reg_totlen_bwd_pkts.write(meta.register_index_inverse, meta.totlen_bwd_pkts);
    	
    	reg_tot_bwd_pkts.read(meta.tot_bwd_pkts, meta.register_index);
    	//reg_totLen_bwd_pkts.read(meta.totLen_bwd_pkts, meta.register_index_inverse);
    	reg_bwd_pkt_len_mean.read(meta.bwd_pkt_len_mean, meta.register_index_inverse);
    	
    	meta.bwd_pkt_len_mean = meta.totlen_bwd_pkts << meta.tot_bwd_pkts;
    	
    	reg_bwd_pkt_len_mean.write(meta.register_index_inverse, meta.bwd_pkt_len_mean);
    }
    
    /*as it can be seen, the mean is evaluated by following the same way of reason of the rates: 
    the register of the packets are firstly red to be accessed, then through bit-shifting the value
    meta.totLen_bwd_pkts is bit-shifted to the right against meta.packets; at the end, the value is re-written
    in the relative register*/


    
    /*the next four actions, when applied, marks the maximum and the minimum length value for, respectevely, 
    the forwarding and backwarding directions*/

    /*the approach adopted is quite simple, as always the register is red to access at the position of the feature in the flow and so to the 5-tuple,
    a metadata is initialised before to be put under condition:
    - for the max: if the value of the packet in the flow is higher than the previous one, then it will be the maximum one;
    - for the min: if the value of the packet in the flow is lower than the previous one, then it will be the minimum one;*/
    
    action calc_max_fwd() {
    	reg_fwd_pkt_len_max.read(meta.fwd_pkt_len_max, meta.register_index_2);
    	//meta.fwd_pkt_len_max = hdr.ipv4.totalLen;
    	if (hdr.ipv4.totalLen > meta.fwd_pkt_len_max) {
    		meta.fwd_pkt_len_max = hdr.ipv4.totalLen;
    	}
    	reg_fwd_pkt_len_max.write(meta.register_index_2, meta.fwd_pkt_len_max);
    }
    
    
    
    
    action calc_min_fwd() {
    	reg_fwd_pkt_len_min.read(meta.fwd_pkt_len_min, meta.register_index_2);
    	meta.fwd_pkt_len_min = hdr.ipv4.totalLen;
    	if (hdr.ipv4.totalLen < meta.fwd_pkt_len_min) {
    		meta.fwd_pkt_len_min = hdr.ipv4.totalLen;
    	}
    	reg_fwd_pkt_len_min.write(meta.register_index_2, meta.fwd_pkt_len_min);
    }    



    action calc_max_bwd() {
    	reg_bwd_pkt_len_max.read(meta.bwd_pkt_len_max, meta.register_index_inverse);
    	//meta.bwd_pkt_len_max = hdr.ipv4.totalLen;
    	if (hdr.ipv4.totalLen > meta.bwd_pkt_len_max) {
    		meta.bwd_pkt_len_max = hdr.ipv4.totalLen;
    	}
    	reg_bwd_pkt_len_max.write(meta.register_index_inverse, meta.bwd_pkt_len_max);
    }
    
    
    
    action calc_min_bwd() {
    	reg_bwd_pkt_len_min.read(meta.bwd_pkt_len_min, meta.register_index_inverse);
    	meta.bwd_pkt_len_min = hdr.ipv4.totalLen;
    	if (hdr.ipv4.totalLen < meta.bwd_pkt_len_min) {
    		meta.bwd_pkt_len_min = hdr.ipv4.totalLen;
    	}
    	reg_bwd_pkt_len_min.write(meta.register_index_inverse, meta.bwd_pkt_len_min);
    }
      
    
    
    //the next two actions represent the maximum and the minimum value of the packet length
    action packet_len_max() {
    	reg_pkt_len_max.read(meta.pkt_len_max, meta.register_index);
    	//meta.pkt_len_max = 0;
    	if (hdr.ipv4.totalLen > meta.pkt_len_max) {
    		meta.pkt_len_max = hdr.ipv4.totalLen;
    	}
    	reg_pkt_len_max.write(meta.register_index, meta.pkt_len_max);
    }
    
    action packet_len_min() {
    	reg_pkt_len_min.read(meta.pkt_len_min, meta.register_index);
    	meta.pkt_len_min = hdr.ipv4.totalLen;
    	if (hdr.ipv4.totalLen < meta.pkt_len_min) {
    		meta.pkt_len_min = hdr.ipv4.totalLen;
    	}
    	reg_pkt_len_min.write(meta.register_index, meta.pkt_len_min);    	
    }
    
    
    //the following action evaluate the mean of the packet length, taking into account the total amount of packets for the average.
    action packet_len_mean() {
    	reg_totLen_pkts.read(meta.totLen_pkts, meta.register_index);
    	meta.totLen_pkts = meta.totLen_pkts + hdr.ipv4.totalLen; //(bit<16>)standard_metadata.packet_length;
    	reg_totLen_pkts.write(meta.register_index, meta.totLen_pkts);
    	
    	reg_packets.read(meta.packets, meta.register_index);
    	//reg_totLen_pkts.read(meta.totLen_pkts, meta.register_index);
    	reg_pkt_len_mean.read(meta.pkt_len_mean, meta.register_index);
    	
    	meta.pkt_len_mean = meta.totLen_pkts << meta.packets;
    	
    	reg_pkt_len_mean.write(meta.register_index, meta.pkt_len_mean);
    }
    
    
    
    action fwd_header() {
    	reg_fwd_header_len.read(meta.fwd_header_len, (bit<32>)meta.register_index_2);
    	reg_fwd_seg_size_min.read(meta.fwd_seg_size_min, meta.register_index_2);
    	
    	if (hdr.ipv4.protocol == 6) {    	
    		meta.fwd_header_len = (bit<16>)hdr.ipv4.ihl*4;
    	}
    	else{
    		meta.fwd_header_len = (bit<16>)8;
    	}

	meta.fwd_seg_size_min = meta.fwd_header_len;	
	
    	if( meta.fwd_header_len <= meta.fwd_seg_size_min) {
    		meta.fwd_seg_size_min = meta.fwd_header_len;
    	}
    	   	
    	reg_fwd_seg_size_min.write(meta.register_index_2, meta.fwd_seg_size_min);
    	meta.fwd_header_len = (meta.fwd_header_len)*((bit<16>)meta.tot_fwd_pkts);
    	reg_fwd_header_len.write(meta.register_index_2, meta.fwd_header_len);
    }
    
    
    
    action bwd_header() {
    	reg_bwd_header_len.read(meta.bwd_header_len, (bit<32>)meta.register_index);

    	if (hdr.ipv4.protocol == 6){
		meta.bwd_header_len = (bit<16>)hdr.ipv4.ihl*4;
	}
	else{
    		meta.bwd_header_len = (bit<16>)8;
    	}
        meta.bwd_header_len = (meta.bwd_header_len)*((bit<16>)meta.tot_bwd_pkts);
        
    	reg_bwd_header_len.write((bit<32>)meta.register_index, meta.bwd_header_len);
    }
    

  
    action count_payload() {
    	reg_fwd_act_data_pkts.read(meta.register_index_2, meta.fwd_act_data_pkts);
    	if(hdr.ethernet.etherType == 0x800 && hdr.ipv4.protocol == 6) { /*this is the case of count payload TCP packets, where
    									  the control is done on the dataOffset field of the header
    									  because dataOffset stands for the offset of the payload and if this 
    									  value is higher than 5 (which is the minimum allowed value and it
    									  corresponds to an offset of five 32 bits words, in other words 20 bytes.)
    									  If the condition is true, this means that there are more features respect 
    									  to the basic TCP header, furthermore this means that the payload begins further on in the packet.*/
    		if(hdr.tcp.dataOffset > 5) {
    			meta.fwd_act_data_pkts = meta.fwd_act_data_pkts + 1; 
    		}
    	}
    	else if(hdr.ethernet.etherType == 0x800 && hdr.ipv4.protocol == 17)  {/* in this case, the the count concerns the UDP packets
    										since the UDP is has a simpler structure than the TCP one
    										the control is on the length of the packet itself: the
    										standard length of the packet is 8 byte, so if the length 
    										is higher, the packet contains payload */
        	if(hdr.udp.length > 8) {
        		meta.fwd_act_data_pkts = meta.fwd_act_data_pkts + 1;
        	}
    		
    	}
    	
    	reg_fwd_act_data_pkts.write(meta.register_index_2, meta.fwd_act_data_pkts);
    }
    
    
   //the next actions concern the operations about the inter-arrival time (time between two consecutive packets)
   action iat_mean() {
   	reg_time_first_pkt.read(meta.time_first_pkt,meta.register_index);
   	reg_iat.read(meta.iat,meta.register_index);
   	
   	//after the iat register is red, register which stores the values
   	meta.iat = (bit<32>)standard_metadata.ingress_global_timestamp - meta.time_first_pkt;
   	reg_iat.write(meta.register_index, meta.iat);
   	
   	reg_packets.read(meta.packets, meta.register_index);
   	reg_iat.read(meta.iat, meta.register_index);
   	 
   	 //evaluation of the inter-arrival time mean 
   	reg_flow_iat_mean.read(meta.flow_iat_mean, meta.register_index);
   	meta.flow_iat_mean = meta.iat << meta.packets;
   	reg_flow_iat_mean.write(meta.register_index, meta.flow_iat_mean);
  	
   }
   
   action iat_max() {   	
   	//finding the inter-arrival time max value
   	reg_flow_iat_max.read(meta.flow_iat_max, meta.register_index);
   	reg_iat.read(meta.iat, meta.register_index);
   	//meta.flow_iat_max = (bit<32>) 0;
   	if(meta.iat > meta.flow_iat_max) {
   		meta.flow_iat_max = meta.iat;
   	}
   	reg_flow_iat_max.write(meta.register_index, meta.flow_iat_max);
   }
   
   
   
   action iat_min() {   	
   	//finding the inter-arrival time max value
   	reg_flow_iat_min.read(meta.flow_iat_min, meta.register_index);
   	reg_iat.read(meta.iat, meta.register_index);
   	meta.flow_iat_min = meta.iat;
   	if(meta.iat < meta.flow_iat_min) {
   		meta.flow_iat_min = meta.iat;

   	}
   	reg_flow_iat_min.write(meta.register_index, meta.flow_iat_min);
   }



   action fwd_iat_tot_mean() {
   	reg_time_first_pkt.read(meta.time_first_pkt, meta.register_index);
   	reg_fwd_iat.read(meta.fwd_iat, meta.register_index_2);
   	reg_fwd_iat_tot.read(meta.fwd_iat_tot, meta.register_index_2);
   	
   	meta.fwd_iat_tot = (bit<32>) 0;
   	meta.fwd_iat = (bit<32>)standard_metadata.ingress_global_timestamp - meta.time_first_pkt;
   	meta.fwd_iat_tot = meta.fwd_iat_tot + meta.fwd_iat;
   	   	  	
   	reg_fwd_iat.write(meta.register_index_2, meta.fwd_iat);
   	reg_fwd_iat_tot.write(meta.register_index_2, meta.fwd_iat_tot);
   	
   	reg_tot_fwd_pkts.read(meta.tot_fwd_pkts, meta.register_index_2);
   	reg_fwd_iat_tot.read(meta.fwd_iat_tot, meta.register_index_2);
   	 
   	 //evaluation of the inter-arrival time mean 
   	reg_fwd_iat_mean.read(meta.fwd_iat_mean, meta.register_index_2);
   	meta.fwd_iat_mean = meta.fwd_iat_tot << meta.tot_fwd_pkts;
   	reg_fwd_iat_mean.write(meta.register_index_2, meta.fwd_iat_mean);
  	
   }   
    

   action fwd_iat_max() {   	
   	//finding the inter-arrival time max value
   	reg_fwd_iat_max.read(meta.fwd_iat_max, meta.register_index_2);
   	reg_fwd_iat.read(meta.fwd_iat, meta.register_index_2);
   	//meta.fwd_iat_max = (bit<32>) 0;
   	if(meta.fwd_iat > meta.fwd_iat_max) {
   		meta.fwd_iat_max = meta.fwd_iat;
   		
   	}
   	reg_fwd_iat_max.write(meta.register_index_2, meta.fwd_iat_max);
   }
   
   
   
   action fwd_iat_min() {   	
   	//finding the inter-arrival time max value
   	reg_fwd_iat_min.read(meta.fwd_iat_min, meta.register_index_2);
   	reg_fwd_iat.read(meta.fwd_iat, meta.register_index_2);
   	meta.fwd_iat_min = meta.fwd_iat;
   	if(meta.fwd_iat < meta.fwd_iat_min) {
   		meta.fwd_iat_min = meta.fwd_iat;
   		
   	}
   	reg_fwd_iat_min.write(meta.register_index_2, meta.fwd_iat_min);
   }
    


   action bwd_iat_tot_mean() {
   	reg_time_first_pkt.read(meta.time_first_pkt, meta.register_index_inverse);
   	reg_bwd_iat.read(meta.bwd_iat, meta.register_index_inverse);
   	reg_bwd_iat_tot.read(meta.bwd_iat_tot, meta.register_index_inverse);
   	
   	meta.bwd_iat_tot = (bit<32>) 0;
   	meta.bwd_iat = (bit<32>)standard_metadata.ingress_global_timestamp - meta.time_first_pkt;
   	meta.bwd_iat_tot = meta.bwd_iat_tot + meta.bwd_iat;
   	   	  	
   	reg_bwd_iat.write(meta.register_index_inverse, meta.bwd_iat);
   	reg_bwd_iat_tot.write(meta.register_index_inverse, meta.bwd_iat_tot);
   	
   	reg_tot_bwd_pkts.read(meta.tot_bwd_pkts, meta.register_index_inverse);
   	reg_bwd_iat_tot.read(meta.bwd_iat_tot, meta.register_index_inverse);
   	 
   	 //evaluation of the inter-arrival time mean 
   	reg_bwd_iat_mean.read(meta.bwd_iat_mean, meta.register_index_inverse);
   	meta.bwd_iat_mean = meta.bwd_iat_tot << meta.tot_bwd_pkts;
   	reg_bwd_iat_mean.write(meta.register_index_inverse, meta.bwd_iat_mean);
  	
   }   
    

   action bwd_iat_max() {   	
   	//finding the inter-arrival time max value
   	reg_bwd_iat_max.read(meta.bwd_iat_max, meta.register_index_inverse);
   	reg_bwd_iat.read(meta.bwd_iat, meta.register_index_inverse);

   	if(meta.bwd_iat_max > meta.bwd_iat) {
   		meta.bwd_iat_max = meta.bwd_iat;
   		
   	}
   	reg_bwd_iat_max.write(meta.register_index_inverse, meta.bwd_iat_max);
   }
   
   
   
   action bwd_iat_min() {   	
   	//finding the inter-arrival time max value
   	reg_bwd_iat_min.read(meta.bwd_iat_min, meta.register_index_inverse);
   	reg_bwd_iat.read(meta.bwd_iat, meta.register_index_inverse);
   	meta.bwd_iat_min = meta.bwd_iat;
   	if(meta.bwd_iat_min < meta.bwd_iat) {
   		meta.bwd_iat_min = meta.bwd_iat;
   		
   	}
   	reg_bwd_iat_min.write(meta.register_index_inverse, meta.bwd_iat_min);
   }




   
    action window_fwd() {
    	reg_init_fwd_win_byts.read(meta.init_fwd_win_byts, meta.register_index_2);
    	meta.init_fwd_win_byts = hdr.tcp.window;
    	reg_init_fwd_win_byts.write(meta.register_index_2, meta.init_fwd_win_byts);
    }
    
    
    action window_bwd() {
    	reg_init_bwd_win_byts.read(meta.init_bwd_win_byts, meta.register_index_inverse);
    	meta.init_bwd_win_byts = hdr.tcp.window;
    	reg_init_bwd_win_byts.write(meta.register_index_inverse, meta.init_bwd_win_byts);
    }
    
     
    
    //the action is about the evaluation of the total amount of the bytes per bulk packets, the mean and the rate
    //the rate is calculated here and in the next action, its average is showedS
    action fwd_b_bytes_count_rate() {
    	reg_fwd_byts_b.read(meta.fwd_byts_b, meta.register_index_2);
    	reg_fwd_byts_b_tot.read(meta.fwd_byts_b_tot, meta.register_index_2);
    	
    	//total
    	meta.fwd_byts_b_tot = meta.fwd_byts_b_tot + meta.fwd_byts_b;
    	
    	//mean
    	reg_fwd_byts_b_avg.read(meta.fwd_byts_b_avg, meta.register_index_2);
    	meta.fwd_byts_b_avg = meta.fwd_byts_b_tot << meta.fwd_b_pkts;
    	
    	//rate
    	reg_fwd_rate_b.read(meta.fwd_rate_b, meta.register_index_2);
    	meta.fwd_rate_b = meta.fwd_byts_b_tot << (bit<8>)meta.flow_duration;
    	
    	reg_fwd_byts_b_tot.write(meta.register_index_2, meta.fwd_byts_b_tot);
    	reg_fwd_byts_b_avg.write(meta.register_index_2, meta.fwd_byts_b_avg);
    	reg_fwd_rate_b.write(meta.register_index_2, meta.fwd_rate_b);
    
    } 



    //same as before, but for backward direction
    action bwd_b_bytes_count_rate() {
    	reg_bwd_byts_b.read(meta.bwd_byts_b, meta.register_index_inverse);
    	reg_bwd_byts_b_tot.read(meta.bwd_byts_b_tot, meta.register_index_inverse);
    	
    	meta.bwd_byts_b_tot = meta.bwd_byts_b_tot + meta.bwd_byts_b;
    	
    	//mean
    	reg_bwd_byts_b_avg.read(meta.bwd_byts_b_avg, meta.register_index_inverse);
    	meta.bwd_byts_b_avg = meta.bwd_byts_b_tot << meta.bwd_b_pkts;
    	
    	//rate
    	reg_bwd_rate_b.read(meta.bwd_rate_b, meta.register_index_inverse);
    	meta.bwd_rate_b = meta.bwd_byts_b_tot << (bit<8>)meta.flow_duration;
    	
    	reg_bwd_byts_b_tot.write(meta.register_index_inverse, meta.bwd_byts_b_tot);
    	reg_bwd_byts_b_avg.write(meta.register_index_inverse, meta.bwd_byts_b_avg);
    	reg_bwd_rate_b.write(meta.register_index_inverse, meta.bwd_rate_b);
    
    } 



    //the rates are grouped in order to calculate the total amount and its mean(that is a feature)
    action fwd_rate_mean() {
        reg_fwd_rate_b.read(meta.fwd_rate_b, meta.register_index_2);
    	reg_fwd_rate_b_tot.read(meta.fwd_rate_b, meta.register_index_2);
    	
    	meta.fwd_rate_b_tot = meta.fwd_rate_b_tot + meta.fwd_rate_b;
    	
    	reg_fwd_blk_rate_avg.read(meta.fwd_blk_rate_avg, meta.register_index_2);
    	meta.fwd_blk_rate_avg = meta.fwd_rate_b_tot << meta.fwd_b_pkts;
    	
    	
    	reg_fwd_rate_b_tot.write(meta.register_index_2, meta.fwd_rate_b);
    	reg_fwd_blk_rate_avg.write(meta.register_index_2, meta.fwd_blk_rate_avg);
    	 
    }


    
    //backward rate mean	
    action bwd_rate_mean() {
        reg_bwd_rate_b.read(meta.bwd_rate_b, meta.register_index_inverse);
    	reg_bwd_rate_b_tot.read(meta.bwd_rate_b, meta.register_index_inverse);
    	
    	meta.bwd_rate_b_tot = meta.bwd_rate_b_tot + meta.bwd_rate_b;
    	
    	reg_bwd_blk_rate_avg.read(meta.bwd_blk_rate_avg, meta.register_index_inverse);
    	meta.bwd_blk_rate_avg = meta.bwd_rate_b_tot << meta.bwd_b_pkts;
    	
    	
    	reg_bwd_rate_b_tot.write(meta.register_index_inverse, meta.bwd_rate_b);
    	reg_bwd_blk_rate_avg.write(meta.register_index_inverse, meta.bwd_blk_rate_avg);
    	 
    }


    //this is to evaluate the mean of the packets sent (forward)
    action fwd_pkts_mean() {
    	reg_fwd_b_pkts.read(meta.fwd_b_pkts, meta.register_index_2);
    	reg_fwd_pkts_b_tot.read(meta.fwd_pkts_b_tot, meta.register_index_2);
    	
    	meta.fwd_pkts_b_tot = meta.fwd_pkts_b_tot + meta.fwd_b_pkts;
    	
    	reg_fwd_pkts_b_avg.read(meta.fwd_pkts_b_avg, meta.register_index_2);
    	meta.fwd_pkts_b_avg = meta.fwd_pkts_b_tot << meta.fwd_b_pkts;
    	
    	reg_fwd_pkts_b_tot.write(meta.register_index_2, meta.fwd_pkts_b_tot);
    	reg_fwd_pkts_b_avg.write(meta.register_index_2, meta.fwd_pkts_b_avg);
    }
    
    
    //backward packets mean
    action bwd_pkts_mean() {
    	reg_bwd_b_pkts.read(meta.bwd_b_pkts, meta.register_index_inverse);
    	reg_bwd_pkts_b_tot.read(meta.bwd_pkts_b_tot, meta.register_index_inverse);
    	
    	meta.bwd_pkts_b_tot = meta.bwd_pkts_b_tot + meta.bwd_b_pkts;
    	
    	reg_bwd_pkts_b_avg.read(meta.bwd_pkts_b_avg, meta.register_index_inverse);
    	meta.bwd_pkts_b_avg = meta.bwd_pkts_b_tot << meta.bwd_b_pkts;
    	
    	reg_bwd_pkts_b_tot.write(meta.register_index_inverse, meta.bwd_pkts_b_tot);
    	reg_bwd_pkts_b_avg.write(meta.register_index_inverse, meta.bwd_pkts_b_avg);
    }


	
    

    /* This will send the packet to a specifique port of the switch for output*/
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
	}
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
 
    
    table ip_first {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = { 
    			first_features;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    table lifetime {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = { 
    			calc_dur;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    table fbt {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = { 
    			flow_bytes_tot;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    table fpt {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = { 
    			flow_pkts_tot;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    table fpr {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = { 
    			flow_pkts_rate;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    table plx {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = { 
    			packet_len_max;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    table plm {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = { 
    			packet_len_min;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    table pav {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = { 
    			packet_len_mean;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    table imn {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = { 
    			iat_mean;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    table iax {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = { 
    			iat_max;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    table imi {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = { 
    			iat_min;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    
    table act_me {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = {
    			active_mean;
    			NoAction;
    		}
    		size = 512;   	
    }
    
    
    table act_mi {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = {
    			active_min;
    			NoAction;
    		}
    		size = 512;  	
    }    
    
 
    table act_ma {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = {
    			active_max;
    			NoAction;
    		}
    		size = 512;    	
    }       
    


    table id_me {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = {
    			idle_mean;
    			NoAction;
    		}
    		size = 512;   	
    }
    
    
    table id_mi {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = {
    			idle_min;
    			NoAction;
    		}
    		size = 512;   	
    }    
    
 
    table id_ma {
    		key = {
    			meta.register_index: exact;
    		}
    		actions = {
    			idle_max;
    			NoAction;
    		}
    		size = 512;   	
    }  


    
// forwarding operations    

    
    table crpf {
    	key = {
    		meta.register_index_2: exact;
    	}
    	actions = {
    		count_and_rate_pkts_fwd;
    		NoAction;
    	}
    	size = 512;
    }
    
    table cff {
    	key = {
    		meta.register_index_2: exact;
    	}
    	actions = {
    		count_fwd_flags;
    		NoAction;
    	}
    	size = 512;
    }
    
    table clfm {
    	key = {
    		meta.register_index_2: exact;
    	}
    	actions = {
    		calc_Length_fwd_tot_mean;
    		NoAction;
    	}
    	size = 512;
    }
    
    
    table cxf {
    	key = {
    		meta.register_index_2: exact;
    	}
    	actions = {
    		calc_max_fwd;
    		NoAction;
    	}
    	size = 512;
    }
    
    
    table cmf {
    	key = {
    		meta.register_index_2: exact;
    	}
    	actions = {
    		calc_min_fwd;
    		NoAction;
    	}
    	size = 512;
    }
    
    
    table fhd {
    	key = {
    		meta.register_index_2: exact;
    	}
    	actions = {
    		fwd_header;
    		NoAction;
    	}
    	size = 512;
    }
    

    table cpd {
    	key = {
    		meta.register_index_2: exact;
    	}
    	actions = {
    		count_payload;
    		NoAction;
    	}
    	size = 512;
    }   


    table fiam {
    	key = {
    		meta.register_index_2: exact;
    	}
    	actions = {
    		fwd_iat_tot_mean;
    		NoAction;
    	}
    	size = 512;
    }
    
    
    table fix {
    	key = {
    		meta.register_index_2: exact;
    	}
    	actions = {
    		fwd_iat_max;
    		NoAction;
    	}
    	size = 512;
    }
    
    table fim {
    	key = {
    		meta.register_index_2: exact;
    	}
    	actions = {
    		fwd_iat_min;
    		NoAction;
    	}
    	size = 512;
    }
    
    
    table wf {
    	key = {
    		meta.register_index_2: exact;
    	}
    	actions = {
    		window_fwd;
    		NoAction;
    	}
    	size = 512;
    }    
    


    table ffpt {
    		key = {
    			meta.register_index_2: exact;
    		}
    		actions = { 
    			fwd_b_flow_pkts_tot;
    			NoAction;
    		}
    		size = 512;
    }



    
    
    table ffbt {
    		key = {
    			meta.register_index_2: exact;
    		}
    		actions = { 
    			fwd_flow_bytes_tot;
    			NoAction;
    		}
    		size = 512;
    }
    
    
    
    table ffbcr {
    		key = {
    			meta.register_index_2: exact;
    		}
    		actions = { 
    			fwd_b_bytes_count_rate;
    			NoAction;
    		}
    		size = 512;
    }    
    


    table fwrm {
    		key = {
    			meta.register_index_2: exact;
    		}
    		actions = { 
    			fwd_rate_mean;
    			NoAction;
    		}
    		size = 512;
    } 



    table fwpm {
    		key = {
    			meta.register_index_2: exact;
    		}
    		actions = { 
    			fwd_pkts_mean;
    			NoAction;
    		}
    		size = 512;
    }


 // backwarding operations   
    
 
    
    table crpb {
    	key = {
    		meta.register_index_inverse: exact;
    	}
    	actions = {
    		count_and_rate_pkts_bwd;
    		NoAction;
    	}
    	size = 512;
    }
    
    
    table cbf {
    	key = {
    		meta.register_index_inverse: exact;
    	}
    	actions = {
    		count_bwd_flags;
    		NoAction;
    	}
    	size = 512;
    }
    
    
    table clbm {
    	key = {
    		meta.register_index_inverse: exact;
    	}
    	actions = {
    		calc_Length_bwd_tot_mean;
    		NoAction;
    	}
    	size = 512;
    }
    
    
    table cxb {
    	key = {
    		meta.register_index_inverse: exact;
    	}
    	actions = {
    		calc_max_bwd;
    		NoAction;
    	}
    	size = 512;
    }
    
    
    table cmb {
    	key = {
    		meta.register_index_inverse: exact;
    	}
    	actions = {
    		calc_min_bwd;
    		NoAction;
    	}
    	size = 512;
    }
    
    
    table bdh {
    	key = {
    		meta.register_index_inverse: exact;
    	}
    	actions = {
    		bwd_header;
    		NoAction;
    	}
    	size = 512;
    }
    


    table biam {
    	key = {
    		meta.register_index_inverse: exact;
    	}
    	actions = {
    		bwd_iat_tot_mean;
    		NoAction;
    	}
    	size = 512;
    }
    
    
    table bix {
    	key = {
    		meta.register_index_inverse: exact;
    	}
    	actions = {
    		bwd_iat_max;
    		NoAction;
    	}
    	size = 512;
    }

   
    table bim {
    	key = {
    		meta.register_index_inverse: exact;
    	}
    	actions = {
    		bwd_iat_min;
    		NoAction;
    	}
    	size = 512;
    }



   
    table wb {
    	key = {
    		meta.register_index_inverse: exact;
    	}
    	actions = {
    		window_bwd;
    		NoAction;
    	}
    	size = 512;
    } 



    table bfpt {
    		key = {
    			meta.register_index_inverse: exact;
    		}
    		actions = { 
    			bwd_b_flow_pkts_tot;
    			NoAction;
    		}
    		size = 512;
    }




    table bfbt {
    		key = {
    			meta.register_index_inverse: exact;
    		}
    		actions = { 
    			bwd_flow_bytes_tot;
    			NoAction;
    		}
    		size = 512;
    }    


    table bfbcr {
    		key = {
    			meta.register_index_inverse: exact;
    		}
    		actions = { 
    			bwd_b_bytes_count_rate;
    			NoAction;
    		}
    		size = 512;
    }


    table bwrm {
    		key = {
    			meta.register_index_inverse: exact;
    		}
    		actions = { 
    			bwd_rate_mean;
    			NoAction;
    		}
    		size = 512;
    }



    table bwpm {
    		key = {
    			meta.register_index_inverse: exact;
    		}
    		actions = { 
    			bwd_pkts_mean;
    			NoAction;
    		}
    		size = 512;
    }





    apply {
    
      	    if (hdr.ipv4.isValid()) {
		//Calculate all features
			      	
		if (hdr.ipv4.protocol == 6 || hdr.ipv4.protocol == 17) {
				
				reg_time_first_pkt.write(meta.register_index, (bit<32>)standard_metadata.ingress_global_timestamp);

		//these conditions concern the operations related to the normal flow and not the forward and backwards operations
				if (hdr.ipv4.protocol == 6) {
					get_register_index_tcp();
					meta.src_port = hdr.tcp.srcPort;
					meta.dst_port = hdr.tcp.dstPort;
				}
				else {
					get_register_index_udp(); 
					meta.src_port = hdr.udp.srcPort;
					meta.dst_port = hdr.udp.dstPort;
				}	
		  
		  
				reg_time_last_pkt.read(meta.time_last_pkt, meta.register_index); 
						
				if (meta.src_ip == 0) {//It was an empty register
					meta.is_first = 1;
				}
						
						
				else if (((bit<32>)standard_metadata.ingress_global_timestamp - meta.time_last_pkt) > FLOW_TIMEOUT) {
					/*We havent heard from this flow it has been FLOW_TIMEOUT
					We will initialse the register space
					 */
					init_register();
					meta.is_first = 1;
				}

			        ip_first.apply();  
	        	        fbt.apply();
	        		fpt.apply();
				plm.apply();
				plx.apply();
	        		pav.apply();
	        		lifetime.apply();
	        		fpr.apply();
	      				
	      				
	        		imn.apply();
	        		iax.apply();
	        		imi.apply();
	        		act_me.apply();
	        		act_mi.apply();
	        		act_ma.apply();
	        		id_me.apply();
	        		id_mi.apply();
	        		id_ma.apply();								
				
				meta.direction = 0;
				
	      			if (meta.direction == 0) {
	      
						if (hdr.ipv4.protocol == 6) {
							get_register_index_tcp();
							meta.src_port = hdr.tcp.srcPort;
							meta.dst_port = hdr.tcp.dstPort;
						}
						else {
							get_register_index_udp(); 
							meta.src_port = hdr.udp.srcPort;
							meta.dst_port = hdr.udp.dstPort;
						}	
						
						reg_time_last_pkt.read(meta.time_last_pkt, meta.register_index);
						
						if (meta.src_ip == 0) {//It was an empty register
							meta.is_first = 1;
						}
						
						
						else if (((bit<32>)standard_metadata.ingress_global_timestamp - meta.time_last_pkt) > FLOW_TIMEOUT) {
							/*We havent heard from this flow it has been FLOW_TIMEOUT
				  			We will initialse the register space
				 			*/
							init_register();
							meta.is_first = 1;
						}

				crpf.apply();
			        cff.apply();
			        clfm.apply();
			        cxf.apply();
			        cmf.apply();
			        fhd.apply();
			        cpd.apply();
			        
			        fiam.apply();
			        fix.apply();
			        fim.apply();
			        wf.apply();
			        
			        /*since I need some constraint to group the packets for bulk, it concerns a threshold
			        about the bytes of the single packet: if a packet overpasses that value of bytes, the bulk is triggered*/
			         reg_totlen_fwd_pkts.read(meta.totlen_fwd_pkts, meta.register_index_2);
			         if(meta.totlen_fwd_pkts > BULK_THR){
			        	 ffpt.apply();
			        	 ffbt.apply();
			        	 ffbcr.apply();
			        	 fwrm.apply();
					 fwpm.apply();
			         }
								
			        meta.direction = 1;
				}
	      			
				if (meta.direction == 1) {
	      
			        		if (hdr.ipv4.protocol == 6) {
							get_register_index_inverse_tcp();
							meta.src_port = hdr.tcp.dstPort;
							meta.dst_port = hdr.tcp.srcPort;
						}
						else {
							get_register_index_inverse_udp(); 
							meta.src_port = hdr.udp.dstPort;
							meta.dst_port = hdr.udp.srcPort;

						}	
						
						
						reg_time_last_pkt.read(meta.time_last_pkt, meta.register_index);
		
						if (meta.src_ip == 0) {//It was an empty register
							meta.is_first = 1;
						}
						else if (((bit<32>)standard_metadata.ingress_global_timestamp - meta.time_last_pkt) > FLOW_TIMEOUT) {
							/*We havent heard from this flow it has been FLOW_TIMEOUT
				  			We will initialse the register space
				 			*/
							init_register();
							meta.is_first = 1;  
						}

				crpb.apply();
			        cbf.apply();
			        clbm.apply();
			        cxb.apply();
			        cmb.apply();
			        bdh.apply();	
			        		        			
			        biam.apply();
			        bix.apply();
			        bim.apply();
			        			        
				wb.apply();
				 
				 /*since I need some constraint to group the packets for bulk, it concerns a threshold
			        about the bytes of the single packet: if a packet overpasses that value of bytes, the bulk is triggered*/
			         reg_totlen_bwd_pkts.read(meta.totlen_bwd_pkts, meta.register_index_inverse);
			         if(meta.totlen_bwd_pkts > BULK_THR){
			        	 bfpt.apply();
			        	 bfbt.apply();
			        	 bfbcr.apply();
			        	 bwrm.apply();
			        	 bwpm.apply();
			         }
									
				}

	//the following conditions will check if the selected flag is 1 and so, the proper register will be updated
	
	                reg_fin_flag_cnt.read(meta.fin_flag_cnt, meta.register_index); 		
			if (hdr.tcp.fin == (bit<1>) 1) {
				meta.fin_flag_cnt = meta.fin_flag_cnt + 1;
			}
			reg_fin_flag_cnt.write(meta.register_index, meta.fin_flag_cnt);
			
			
		        reg_syn_flag_cnt.read(meta.syn_flag_cnt, meta.register_index);
			if (hdr.tcp.syn == (bit<1>) 1) {
				meta.syn_flag_cnt = meta.syn_flag_cnt + 1;
			}
			reg_syn_flag_cnt.write(meta.register_index, meta.syn_flag_cnt);
			
			
		        reg_rst_flag_cnt.read(meta.rst_flag_cnt, meta.register_index);
			if (hdr.tcp.rst == (bit<1>) 1) {
				meta.rst_flag_cnt = meta.rst_flag_cnt + 1;
			}
			reg_rst_flag_cnt.write(meta.register_index, meta.rst_flag_cnt);
			
			
		        reg_psh_flag_cnt.read(meta.psh_flag_cnt, meta.register_index);
			if (hdr.tcp.psh == (bit<1>) 1) {
				meta.psh_flag_cnt = meta.psh_flag_cnt + 1;
			}
			reg_psh_flag_cnt.write(meta.register_index, meta.psh_flag_cnt);
			
			
		        reg_ack_flag_cnt.read(meta.ack_flag_cnt, meta.register_index);
			if (hdr.tcp.ack == (bit<1>) 1) {
				meta.ack_flag_cnt = meta.ack_flag_cnt + 1;
			}
			reg_ack_flag_cnt.write(meta.register_index, meta.ack_flag_cnt);
			
			
		        reg_urg_flag_cnt.read(meta.urg_flag_cnt, meta.register_index);
			if (hdr.tcp.urg == (bit<1>) 1) {
				meta.urg_flag_cnt = meta.urg_flag_cnt + 1;
			}
			reg_urg_flag_cnt.write(meta.register_index, meta.urg_flag_cnt);
			
			
		        reg_ece_flag_cnt.read(meta.ece_flag_cnt, meta.register_index);
			if (hdr.tcp.ece == (bit<1>) 1) {
				meta.ece_flag_cnt = meta.ece_flag_cnt + 1;
			}
			reg_ece_flag_cnt.write(meta.register_index, meta.ece_flag_cnt);
				
		
		
	                if (meta.packets >= PACKET_THR) {
            			log_msg("Source IP= {}, Destination IP= {}, Source Port= {}, Destination Port= {}, Protocol= {}, Dur= {}, Flow_pkts_rate= {}, Flow_Bytes_rate= {}, HAS_fin= {}, HAS_syn= {}, HAS_rst= {}, HAS_psh= {}, HAS_ack= {}, HAS_urg= {}, HAS_ece= {}, Tot_Fwd_Packets= {}, Tot_Bwd_Packets= {}, Tot_Fwd_Packets_Rate= {}, Tot_Bwd_Packets_Rate= {}, PSH_fwd_flag= {}, URG_fwd_flag= {}, PSH_bwd_flag= {}, URG_bwd_flag= {}, Length_Fwd= {}, Length_Bwd= {}, Min_Fwd_Length= {}, Max_Fwd_Length= {}, Mean_Fwd_Length= {}, Min_Bwd_Length= {}, Max_Bwd_Length= {}, Mean_Bwd_Length= {}, Max_pkt_len= {}, Min_pkt_len= {}, Mean_pkt_len= {}, FWD_HEADER= {}, FWD_SEG_SIZE_MIN= {}, BWD_HEADER= {}, FWD_Window= {}, BWD_Window= {}, FWD_PAY_Packets= {}, FLOW_IAT_MIN= {}, FLOW_IAT_MAX= {}, FLOW_IAT_MEAN= {}, FWD_IAT_MIN= {}, FWD_IAT_MAX= {}, FWD_IAT_TOT= {}, FWD_IAT_MEAN= {}, BWD_IAT_MIN= {}, BWD_IAT_MAX= {}, BWD_IAT_TOT= {}, BWD_IAT_MEAN= {}, Active_mean= {}, Active_min= {}, Active_max= {}, Idle_mean= {}, Idle_min= {}, Idle_max= {}, Bulk_fwd_bytes_avg= {}, Bulk_fwd_pkts_avg= {}, Bulk_fwd_rate_avg= {}, Bulk_bwd_bytes_avg= {}, Bulk_bwd_pkts_avg= {}, Bulk_bwd_rate_avg= {}, Packets= {}, Bytes= {}", {meta.src_ip, meta.dst_ip, meta.src_port, meta.dst_port, meta.protocol, meta.flow_duration, meta.flow_pkts_s, meta.flow_byts_s, meta.fin_flag_cnt, meta.syn_flag_cnt, meta.rst_flag_cnt, meta.psh_flag_cnt, meta.ack_flag_cnt, meta.urg_flag_cnt, meta.ece_flag_cnt, meta.tot_fwd_pkts, meta.tot_bwd_pkts, meta.fwd_pkts_s, meta.bwd_pkts_s, meta.fwd_psh_flags, meta.fwd_urg_flags, meta.bwd_psh_flags, meta.bwd_urg_flags, meta.totlen_fwd_pkts, meta.totlen_bwd_pkts, meta.fwd_pkt_len_min, meta.fwd_pkt_len_max, meta.fwd_pkt_len_mean, meta.bwd_pkt_len_min, meta.bwd_pkt_len_max, meta.bwd_pkt_len_mean, meta.pkt_len_max, meta.pkt_len_min, meta.pkt_len_mean, meta.fwd_header_len, meta.fwd_seg_size_min, meta.bwd_header_len, meta.init_fwd_win_byts, meta.init_bwd_win_byts, meta.fwd_act_data_pkts, meta.flow_iat_min, meta.flow_iat_max, meta.flow_iat_mean, meta.fwd_iat_min, meta.fwd_iat_max, meta.fwd_iat_tot, meta.fwd_iat_mean, meta.bwd_iat_min, meta.bwd_iat_max, meta.bwd_iat_tot, meta.bwd_iat_mean, meta.active_mean, meta.active_min, meta.active_max, meta.idle_mean, meta.idle_min, meta.idle_max, meta.fwd_byts_b_avg, meta.fwd_pkts_b_avg, meta.fwd_blk_rate_avg, meta.bwd_byts_b_avg, meta.bwd_pkts_b_avg, meta.bwd_blk_rate_avg, meta.packets, meta.bytes});
            	        }
            	        			
		

                                }//this is for closing the tcp and udp condition
                                
               		ipv4_lpm.apply();
    
            } //hdr.ipv4.isValid if

       
    } //apply if
    
  
} //egress control if


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
	    HashAlgorithm.csum16);
    }
}

/*************************************************************************

***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;  
