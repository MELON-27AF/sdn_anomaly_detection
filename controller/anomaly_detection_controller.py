from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
import requests
import time
import numpy as np
import logging
import json

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("controller.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger()  # gunakan root logger yang sudah dikonfigurasi

class AnomalyDetectionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AnomalyDetectionController, self).__init__(*args, **kwargs)
        # Konfigurasi edge node - sesuaikan IP dengan edge node Anda
        self.edge_api_url = "http://192.168.33.139:5000/predict"  # Ganti dengan IP edge node

        # Konfigurasi buffer untuk flow
        self.flow_buffer = {}  # Store flow features
        self.sequence_length = 10  # Sequence length sama dengan training (SEQUENCE_LENGTH)

        # Pengaturan feature extraction - sesuaikan dengan model yang dilatih
        # Ini harus disesuaikan dengan fitur yang digunakan saat training
        self.feature_names = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
            'Protocol', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 
            'ACK Flag Count', 'URG Flag Count', 'Flow Bytes/s', 'Flow Packets/s',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
            'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
            'Avg Bwd Segment Size', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
            'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]
        
        self.feature_names = self.feature_names[:47]
        
        self.num_features = len(self.feature_names)
        logger.info(f"Initialized with {self.num_features} features and sequence length {self.sequence_length}")

        # Statistik
        self.detection_count = {'normal': 0, 'anomaly': 0}
        self.blocked_flows = set()

        # Mac address table
        self.mac_to_port = {}

        # Verifikasi koneksi dengan edge node
        self._check_edge_node_connection()

    def _check_edge_node_connection(self):
        """Verifikasi koneksi dengan edge node"""
        try:
            response = requests.get(self.edge_api_url.replace('/predict', '/health'), timeout=5)
            if response.status_code == 200:
                logger.info("Successfully connected to edge node")
            else:
                logger.warning(f"Edge node responded with status code: {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to connect to edge node: {e}")
            logger.warning("Controller will still run, but anomaly detection might not work")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install the table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        logger.info(f"Switch {datapath.id} connected")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, idle_timeout=0):
        """Helper function to add flow entry to switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=hard_timeout,
                                    idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    hard_timeout=hard_timeout,
                                    idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def _extract_flow_features(self, datapath, in_port, pkt):
        """Extract features from packet for model input"""
        # Parse packet
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if not ip_pkt:
            return None, None  # Not an IP packet

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # Create flow identifier
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        protocol = ip_pkt.proto

        src_port = None
        dst_port = None
        tcp_flags = 0

        if tcp_pkt:
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
            # Extract TCP flags
            tcp_flags = 0
            if tcp_pkt.bits & (1 << 0): tcp_flags |= 0x01  # FIN
            if tcp_pkt.bits & (1 << 1): tcp_flags |= 0x02  # SYN
            if tcp_pkt.bits & (1 << 2): tcp_flags |= 0x04  # RST
            if tcp_pkt.bits & (1 << 3): tcp_flags |= 0x08  # PSH
            if tcp_pkt.bits & (1 << 4): tcp_flags |= 0x10  # ACK
            if tcp_pkt.bits & (1 << 5): tcp_flags |= 0x20  # URG
        elif udp_pkt:
            src_port = udp_pkt.src_port
            dst_port = udp_pkt.dst_port

        # Unique flow identifier
        flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"

        # Get current time
        current_time = time.time()

        # Initialize flow if not exists
        if flow_id not in self.flow_buffer:
            self.flow_buffer[flow_id] = {
                'packet_count': 0,
                'fwd_packet_count': 0,
                'bwd_packet_count': 0,
                'total_fwd_bytes': 0,
                'total_bwd_bytes': 0,
                'start_time': current_time,
                'last_time': current_time,
                'pkt_times': [],
                'pkt_sizes': [],
                'fwd_pkt_times': [],
                'bwd_pkt_times': [],
                'active_start': current_time,
                'active_times': [],
                'idle_times': [],
                'fin_count': 0,
                'syn_count': 0,
                'rst_count': 0,
                'psh_count': 0,
                'ack_count': 0,
                'urg_count': 0,
                'fwd_psh_count': 0,
                'bwd_psh_count': 0,
                'fwd_header_bytes': 0,
                'bwd_header_bytes': 0,
                'fwd_init_win': 0,
                'bwd_init_win': 0,
                'active': True,
                'features': []  # Will store generated feature vectors
            }

        # Get flow object
        flow = self.flow_buffer[flow_id]

        # Update flow statistics
        flow['packet_count'] += 1

        # Determine direction (fwd/bwd) based on first packet
        is_forward = True
        if flow['packet_count'] == 1:
            # First packet defines forward direction
            flow['init_src_ip'] = src_ip
            flow['init_dst_ip'] = dst_ip
        else:
            # Check direction based on first packet's src/dst
            is_forward = (src_ip == flow['init_src_ip'])

        # Update direction specific counters
        if is_forward:
            flow['fwd_packet_count'] += 1
            flow['total_fwd_bytes'] += len(pkt.data)
            flow['fwd_pkt_times'].append(current_time)
            if tcp_pkt:
                flow['fwd_header_bytes'] += 20  # Simplified - TCP header size
                if flow['packet_count'] == 1:
                    # Periksa apakah atribut window ada, jika tidak gunakan nilai default
                    try:
                        flow['fwd_init_win'] = tcp_pkt.window
                    except AttributeError:
                        # Nilai default window size 65535 (atau 0 jika tidak ingin membuat asumsi)
                        flow['fwd_init_win'] = 65535  # Default TCP window size

        else:
            flow['bwd_packet_count'] += 1
            flow['total_bwd_bytes'] += len(pkt.data)
            flow['bwd_pkt_times'].append(current_time)
            if tcp_pkt:
                flow['bwd_header_bytes'] += 20  # Simplified - TCP header size
                if flow['packet_count'] == 1:
                    # Periksa apakah atribut window ada, jika tidak gunakan nilai default
                    try:
                        flow['bwd_init_win'] = tcp_pkt.window
                    except AttributeError:
                        # Nilai default window size
                        flow['bwd_init_win'] = 65535  # Default TCP window size

        # Update TCP flag counts
        if tcp_pkt:
            if tcp_pkt.bits & (1 << 0): flow['fin_count'] += 1
            if tcp_pkt.bits & (1 << 1): flow['syn_count'] += 1
            if tcp_pkt.bits & (1 << 2): flow['rst_count'] += 1
            if tcp_pkt.bits & (1 << 3): 
                flow['psh_count'] += 1
                if is_forward: flow['fwd_psh_count'] += 1
                else: flow['bwd_psh_count'] += 1
            if tcp_pkt.bits & (1 << 4): flow['ack_count'] += 1
            if tcp_pkt.bits & (1 << 5): flow['urg_count'] += 1

        # Track packet times and sizes
        flow['pkt_times'].append(current_time)
        flow['pkt_sizes'].append(len(pkt.data))

        # Calculate activity and idle time
        if flow['last_time'] < current_time - 1.0:  # 1 second of inactivity
            if flow['active']:
                # End active period, start idle period
                active_time = flow['last_time'] - flow['active_start']
                flow['active_times'].append(active_time)
                flow['active'] = False
                flow['idle_start'] = flow['last_time']
            else:
                # Continue idle period
                pass
        else:
            if not flow['active']:
                # End idle period, start active period
                idle_time = flow['last_time'] - flow['idle_start']
                flow['idle_times'].append(idle_time)
                flow['active'] = True
                flow['active_start'] = current_time
            else:
                # Continue active period
                pass

        # Update last packet time
        flow['last_time'] = current_time

        # Generate feature vector if we have enough packets
        if flow['packet_count'] >= 2:  # Need at least 2 packets for some features
            # Calculate flow duration
            flow_duration = current_time - flow['start_time']
            if flow_duration == 0: flow_duration = 0.000001  # Avoid division by zero

            # Create feature dictionary
            feature_dict = {}

            # Core features from flow statistics
            feature_dict['Flow Duration'] = flow_duration
            feature_dict['Total Fwd Packets'] = flow['fwd_packet_count']
            feature_dict['Total Backward Packets'] = flow['bwd_packet_count']
            feature_dict['Protocol'] = protocol
            feature_dict['Total Length of Fwd Packets'] = flow['total_fwd_bytes']
            feature_dict['Total Length of Bwd Packets'] = flow['total_bwd_bytes']

            # Flag counts
            feature_dict['FIN Flag Count'] = flow['fin_count']
            feature_dict['SYN Flag Count'] = flow['syn_count']
            feature_dict['RST Flag Count'] = flow['rst_count']
            feature_dict['PSH Flag Count'] = flow['psh_count']
            feature_dict['ACK Flag Count'] = flow['ack_count']
            feature_dict['URG Flag Count'] = flow['urg_count']

            # Flow rates
            feature_dict['Flow Bytes/s'] = (flow['total_fwd_bytes'] + flow['total_bwd_bytes']) / flow_duration
            feature_dict['Flow Packets/s'] = flow['packet_count'] / flow_duration

            # Inter-arrival time (IAT) features
            if len(flow['pkt_times']) > 1:
                # Calculate all packet IATs
                iats = np.diff(flow['pkt_times'])
                if len(iats) > 0:
                    feature_dict['Flow IAT Mean'] = np.mean(iats)
                    feature_dict['Flow IAT Std'] = np.std(iats) if len(iats) > 1 else 0
                    feature_dict['Flow IAT Max'] = np.max(iats)
                    feature_dict['Flow IAT Min'] = np.min(iats)
                else:
                    feature_dict['Flow IAT Mean'] = 0
                    feature_dict['Flow IAT Std'] = 0
                    feature_dict['Flow IAT Max'] = 0
                    feature_dict['Flow IAT Min'] = 0
            else:
                feature_dict['Flow IAT Mean'] = 0
                feature_dict['Flow IAT Std'] = 0
                feature_dict['Flow IAT Max'] = 0
                feature_dict['Flow IAT Min'] = 0

            # Forward IAT features
            if len(flow['fwd_pkt_times']) > 1:
                fwd_iats = np.diff(flow['fwd_pkt_times'])
                if len(fwd_iats) > 0:
                    feature_dict['Fwd IAT Total'] = np.sum(fwd_iats)
                    feature_dict['Fwd IAT Mean'] = np.mean(fwd_iats)
                    feature_dict['Fwd IAT Std'] = np.std(fwd_iats) if len(fwd_iats) > 1 else 0
                    feature_dict['Fwd IAT Max'] = np.max(fwd_iats)
                    feature_dict['Fwd IAT Min'] = np.min(fwd_iats)
                else:
                    feature_dict['Fwd IAT Total'] = 0
                    feature_dict['Fwd IAT Mean'] = 0
                    feature_dict['Fwd IAT Std'] = 0
                    feature_dict['Fwd IAT Max'] = 0
                    feature_dict['Fwd IAT Min'] = 0
            else:
                feature_dict['Fwd IAT Total'] = 0
                feature_dict['Fwd IAT Mean'] = 0
                feature_dict['Fwd IAT Std'] = 0
                feature_dict['Fwd IAT Max'] = 0
                feature_dict['Fwd IAT Min'] = 0

            # Backward IAT features
            if len(flow['bwd_pkt_times']) > 1:
                bwd_iats = np.diff(flow['bwd_pkt_times'])
                if len(bwd_iats) > 0:
                    feature_dict['Bwd IAT Total'] = np.sum(bwd_iats)
                    feature_dict['Bwd IAT Mean'] = np.mean(bwd_iats)
                    feature_dict['Bwd IAT Std'] = np.std(bwd_iats) if len(bwd_iats) > 1 else 0
                    feature_dict['Bwd IAT Max'] = np.max(bwd_iats)
                    feature_dict['Bwd IAT Min'] = np.min(bwd_iats)
                else:
                    feature_dict['Bwd IAT Total'] = 0
                    feature_dict['Bwd IAT Mean'] = 0
                    feature_dict['Bwd IAT Std'] = 0
                    feature_dict['Bwd IAT Max'] = 0
                    feature_dict['Bwd IAT Min'] = 0
            else:
                feature_dict['Bwd IAT Total'] = 0
                feature_dict['Bwd IAT Mean'] = 0
                feature_dict['Bwd IAT Std'] = 0
                feature_dict['Bwd IAT Max'] = 0
                feature_dict['Bwd IAT Min'] = 0

            # PSH Flags
            feature_dict['Fwd PSH Flags'] = flow['fwd_psh_count'] > 0
            feature_dict['Bwd PSH Flags'] = flow['bwd_psh_count'] > 0

            # Header lengths
            feature_dict['Fwd Header Length'] = flow['fwd_header_bytes']
            feature_dict['Bwd Header Length'] = flow['bwd_header_bytes']

            # Packet rates
            feature_dict['Fwd Packets/s'] = flow['fwd_packet_count'] / flow_duration
            feature_dict['Bwd Packets/s'] = flow['bwd_packet_count'] / flow_duration

            # Packet length features
            if len(flow['pkt_sizes']) > 0:
                feature_dict['Min Packet Length'] = np.min(flow['pkt_sizes'])
                feature_dict['Max Packet Length'] = np.max(flow['pkt_sizes'])
                feature_dict['Packet Length Mean'] = np.mean(flow['pkt_sizes'])
                feature_dict['Packet Length Std'] = np.std(flow['pkt_sizes']) if len(flow['pkt_sizes']) > 1 else 0
                feature_dict['Packet Length Variance'] = np.var(flow['pkt_sizes']) if len(flow['pkt_sizes']) > 1 else 0
            else:
                feature_dict['Min Packet Length'] = 0
                feature_dict['Max Packet Length'] = 0
                feature_dict['Packet Length Mean'] = 0
                feature_dict['Packet Length Std'] = 0
                feature_dict['Packet Length Variance'] = 0

            # Down/Up Ratio
            if flow['fwd_packet_count'] > 0:
                feature_dict['Down/Up Ratio'] = flow['bwd_packet_count'] / flow['fwd_packet_count']
            else:
                feature_dict['Down/Up Ratio'] = 0

            # Average packet size
            if flow['packet_count'] > 0:
                feature_dict['Average Packet Size'] = (flow['total_fwd_bytes'] + flow['total_bwd_bytes']) / flow['packet_count']
            else:
                feature_dict['Average Packet Size'] = 0

            # Segment sizes
            if flow['fwd_packet_count'] > 0:
                feature_dict['Avg Fwd Segment Size'] = flow['total_fwd_bytes'] / flow['fwd_packet_count']
            else:
                feature_dict['Avg Fwd Segment Size'] = 0

            if flow['bwd_packet_count'] > 0:
                feature_dict['Avg Bwd Segment Size'] = flow['total_bwd_bytes'] / flow['bwd_packet_count']
            else:
                feature_dict['Avg Bwd Segment Size'] = 0

            # Subflow features (simplified - in real traffic these would be calculated over subflow periods)
            feature_dict['Subflow Fwd Packets'] = flow['fwd_packet_count']
            feature_dict['Subflow Fwd Bytes'] = flow['total_fwd_bytes']
            feature_dict['Subflow Bwd Packets'] = flow['bwd_packet_count']
            feature_dict['Subflow Bwd Bytes'] = flow['total_bwd_bytes']

            # Init window bytes
            feature_dict['Init_Win_bytes_forward'] = flow['fwd_init_win']
            feature_dict['Init_Win_bytes_backward'] = flow['bwd_init_win']

            # Active data packets
            feature_dict['act_data_pkt_fwd'] = 0  # Simplified
            feature_dict['min_seg_size_forward'] = 0  # Simplified

            # Active/Idle time features
            if len(flow['active_times']) > 0:
                feature_dict['Active Mean'] = np.mean(flow['active_times'])
                feature_dict['Active Std'] = np.std(flow['active_times']) if len(flow['active_times']) > 1 else 0
                feature_dict['Active Max'] = np.max(flow['active_times'])
                feature_dict['Active Min'] = np.min(flow['active_times'])
            else:
                feature_dict['Active Mean'] = 0
                feature_dict['Active Std'] = 0
                feature_dict['Active Max'] = 0
                feature_dict['Active Min'] = 0

            if len(flow['idle_times']) > 0:
                feature_dict['Idle Mean'] = np.mean(flow['idle_times'])
                feature_dict['Idle Std'] = np.std(flow['idle_times']) if len(flow['idle_times']) > 1 else 0
                feature_dict['Idle Max'] = np.max(flow['idle_times'])
                feature_dict['Idle Min'] = np.min(flow['idle_times'])
            else:
                feature_dict['Idle Mean'] = 0
                feature_dict['Idle Std'] = 0
                feature_dict['Idle Max'] = 0
                feature_dict['Idle Min'] = 0

            # Create feature vector in correct order
            feature_vector = []
            for feature_name in self.feature_names:
                if feature_name in feature_dict:
                    feature_vector.append(feature_dict[feature_name])
                else:
                    feature_vector.append(0)  # Default value for missing features

            # Normalize feature vector - IMPORTANT!
            # Simplified normalization - in production, use the same scaler as training
            # This is a simple Min-Max scaling assuming all values are between 0-1
            # In real deployment, implement proper scaling using saved scaler parameters from training
            feature_vector = np.clip(feature_vector, 0, 1e6)  # Clip extreme values

            # Add feature vector to flow
            flow['features'].append(feature_vector)

            # Keep only the last 'sequence_length' feature vectors
            if len(flow['features']) > self.sequence_length:
                flow['features'] = flow['features'][-self.sequence_length:]

        return flow_id, flow

    def _detect_anomaly(self, flow_id, flow):
        """Send features to edge node for anomaly detection"""
        if len(flow['features']) < self.sequence_length:
            # Not enough data for sequence
            return False, 0.0
    
        # Get the last sequence_length feature vectors
        sequence = flow['features'][-self.sequence_length:]
    
        try:
            # Convert sequence to list for JSON serialization
            sequence_list = []
            for feature_vector in sequence:
                if hasattr(feature_vector, 'tolist'):
                    # Ambil hanya 47 fitur pertama
                    feature_vector = feature_vector[:47].tolist()
                else:
                    # Ambil hanya 47 fitur pertama
                    feature_vector = list(feature_vector)[:47]
                sequence_list.append(feature_vector)
    
            # Send to edge node for prediction
            payload = {'features': sequence_list}
            response = requests.post(self.edge_api_url, json=payload, timeout=1.0)
    
            if response.status_code == 200:
                result = response.json()
                is_anomaly = result.get('is_anomaly', False)
                prediction = result.get('prediction', 0.0)
                inference_time = result.get('inference_time_ms', 0.0)
    
                # Update statistics
                if is_anomaly:
                    self.detection_count['anomaly'] += 1
                else:
                    self.detection_count['normal'] += 1
    
                logger.info(f"Flow {flow_id}: {'ANOMALY' if is_anomaly else 'NORMAL'} (score: {prediction:.4f}, time: {inference_time:.2f}ms)")
                return is_anomaly, prediction
            else:
                logger.error(f"Edge node error: {response.status_code}, {response.text}")
                return False, 0.0
    
        except Exception as e:
            logger.error(f"Error during anomaly detection: {e}")
            return False, 0.0

    def _handle_anomaly(self, datapath, flow_id, in_port, pkt):
        """Handle detected anomaly - implement blocking rules"""
        logger.warning(f"Handling anomaly for flow: {flow_id}")

        # Check if this flow is already blocked
        if flow_id in self.blocked_flows:
            return

        # Parse packet for matching
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # Get parser and protocol
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Create match based on protocol
        match = parser.OFPMatch(
            eth_type=0x0800,  # IPv4
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst,
            ip_proto=ip_pkt.proto
        )

        # Add transport layer match fields
        if tcp_pkt:
            match.append_field(ofproto.OXM_OF_TCP_SRC, tcp_pkt.src_port)
            match.append_field(ofproto.OXM_OF_TCP_DST, tcp_pkt.dst_port)
        elif udp_pkt:
            match.append_field(ofproto.OXM_OF_UDP_SRC, udp_pkt.src_port)
            match.append_field(ofproto.OXM_OF_UDP_DST, udp_pkt.dst_port)

        # Create empty instruction - drops packet
        instructions = []

        # Add flow entry with high priority and timeout
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=instructions,
            hard_timeout=300  # Block for 5 minutes
        )

        # Send flow mod message to switch
        datapath.send_msg(flow_mod)

        # Add to blocked flows set
        self.blocked_flows.add(flow_id)

        logger.warning(f"Blocked anomalous flow: {flow_id} for 5 minutes")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle packet in events"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Parse packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore non-IP packets
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            # Forward non-IP packets normally
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

            # FIX: Handle buffer_id correctly
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions)
            else:
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data)

            datapath.send_msg(out)
            return

        # Extract flow features
        flow_id, flow = self._extract_flow_features(datapath, in_port, pkt)

        if not flow_id or not flow:
            # If feature extraction failed, forward normally
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

            # FIX: Handle buffer_id correctly
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions)
            else:
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data)

            datapath.send_msg(out)
            return

        # Check for anomaly detection
        if flow['packet_count'] % 2 == 0 and len(flow['features']) >= self.sequence_length:
            # Only run detection periodically (e.g., every 2 packets) to reduce overhead
            is_anomaly, prediction = self._detect_anomaly(flow_id, flow)

            if is_anomaly:
                # Handle anomalous traffic
                self._handle_anomaly(datapath, flow_id, in_port, pkt)
                return  # Drop packet

        # Forward normal traffic
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        # FIX: Handle buffer_id correctly
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions)
        else:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data)

        datapath.send_msg(out)
