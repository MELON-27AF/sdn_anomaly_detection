"""
Feature extraction utility for SDN anomaly detection
Used for consistent feature extraction between controller and testing tools
"""
import numpy as np
import time

class FlowFeatureExtractor:
    """
    Utility class to extract and manage flow features for anomaly detection
    """
    def __init__(self, feature_names=None, sequence_length=10):
        self.sequence_length = sequence_length

        # Default feature set if none provided
        self.feature_names = feature_names or [
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

        self.flow_buffers = {}

    def process_packet(self, flow_id, packet_data):
        """
        Process a packet and update flow features

        Args:
            flow_id: Unique identifier for the flow
            packet_data: Dictionary with packet information
                Required keys:
                - timestamp: packet timestamp
                - size: packet size in bytes
                - header_size: size of header in bytes
                - is_forward: boolean indicating direction
                - flags: dictionary of TCP flags (if TCP)
                - window_size: TCP window size (if TCP)

        Returns:
            Tuple of (flow_id, feature_vector, has_sequence)
            where has_sequence indicates if a full sequence is available
        """
        # Initialize flow if not exists
        if flow_id not in self.flow_buffers:
            self.flow_buffers[flow_id] = {
                'packet_count': 0,
                'fwd_packet_count': 0,
                'bwd_packet_count': 0,
                'total_fwd_bytes': 0,
                'total_bwd_bytes': 0,
                'start_time': packet_data['timestamp'],
                'last_time': packet_data['timestamp'],
                'pkt_times': [],
                'pkt_sizes': [],
                'fwd_pkt_times': [],
                'bwd_pkt_times': [],
                'active_start': packet_data['timestamp'],
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

        # Get flow buffer
        flow = self.flow_buffers[flow_id]

        # Update packet counters
        flow['packet_count'] += 1
        if packet_data['is_forward']:
            flow['fwd_packet_count'] += 1
            flow['total_fwd_bytes'] += packet_data['size']
            flow['fwd_pkt_times'].append(packet_data['timestamp'])
            flow['fwd_header_bytes'] += packet_data.get('header_size', 0)

            # Set initial window size if first packet
            if flow['fwd_packet_count'] == 1 and 'window_size' in packet_data:
                flow['fwd_init_win'] = packet_data.get('window_size', 0)

            # Update PSH flag count
            if packet_data.get('flags', {}).get('psh', False):
                flow['fwd_psh_count'] += 1
        else:
            flow['bwd_packet_count'] += 1
            flow['total_bwd_bytes'] += packet_data['size']
            flow['bwd_pkt_times'].append(packet_data['timestamp'])
            flow['bwd_header_bytes'] += packet_data.get('header_size', 0)

            # Set initial window size if first packet
            if flow['bwd_packet_count'] == 1 and 'window_size' in packet_data:
                flow['bwd_init_win'] = packet_data.get('window_size', 0)

            # Update PSH flag count
            if packet_data.get('flags', {}).get('psh', False):
                flow['bwd_psh_count'] += 1

        # Update TCP flags if present
        if 'flags' in packet_data:
            flags = packet_data['flags']
            if flags.get('fin', False): flow['fin_count'] += 1
            if flags.get('syn', False): flow['syn_count'] += 1
            if flags.get('rst', False): flow['rst_count'] += 1
            if flags.get('psh', False): flow['psh_count'] += 1
            if flags.get('ack', False): flow['ack_count'] += 1
            if flags.get('urg', False): flow['urg_count'] += 1

        # Add to general packet arrays
        flow['pkt_times'].append(packet_data['timestamp'])
        flow['pkt_sizes'].append(packet_data['size'])

        # Calculate active/idle time
        current_time = packet_data['timestamp']
        if flow['last_time'] < current_time - 1.0:  # 1 second threshold
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

        # Update last time
        flow['last_time'] = current_time

        # Generate features if we have enough packets
        feature_vector = None
        has_sequence = False

        if flow['packet_count'] >= 2:  # Need at least 2 packets for meaningful features
            # Calculate features
            feature_vector = self._calculate_flow_features(flow)

            # Add to sequence
            flow['features'].append(feature_vector)

            # Keep only last sequence_length features
            if len(flow['features']) > self.sequence_length:
                flow['features'] = flow['features'][-self.sequence_length:]

            # Check if we have a full sequence
            has_sequence = len(flow['features']) >= self.sequence_length

        return flow_id, feature_vector, has_sequence

    def get_sequence(self, flow_id):
        """
        Get the current sequence for a flow if available

        Args:
            flow_id: Flow identifier

        Returns:
            Numpy array of shape [sequence_length, num_features] or None if not enough data
        """
        if flow_id not in self.flow_buffers:
            return None

        flow = self.flow_buffers[flow_id]
        if len(flow['features']) < self.sequence_length:
            return None

        # Return last sequence_length features as numpy array
        return np.array(flow['features'][-self.sequence_length:], dtype=np.float32)

    def _calculate_flow_features(self, flow):
        """
        Calculate features from flow statistics

        Args:
            flow: Flow buffer dictionary

        Returns:
            List of features in the order specified by feature_names
        """
        # Calculate flow duration
        flow_duration = flow['last_time'] - flow['start_time']
        if flow_duration == 0: flow_duration = 0.000001  # Prevent division by zero

        # Create feature dictionary
        feature_dict = {}

        # Core features
        feature_dict['Flow Duration'] = flow_duration
        feature_dict['Total Fwd Packets'] = flow['fwd_packet_count']
        feature_dict['Total Backward Packets'] = flow['bwd_packet_count']
        feature_dict['Protocol'] = 0  # Not stored in this utility - must be provided externally
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

        # IAT (Inter-Arrival Time) features
        if len(flow['pkt_times']) > 1:
            iats = np.diff(flow['pkt_times'])
            feature_dict['Flow IAT Mean'] = np.mean(iats)
            feature_dict['Flow IAT Std'] = np.std(iats) if len(iats) > 1 else 0
            feature_dict['Flow IAT Max'] = np.max(iats)
            feature_dict['Flow IAT Min'] = np.min(iats)
        else:
            feature_dict['Flow IAT Mean'] = 0
            feature_dict['Flow IAT Std'] = 0
            feature_dict['Flow IAT Max'] = 0
            feature_dict['Flow IAT Min'] = 0

        # Forward IAT features
        if len(flow['fwd_pkt_times']) > 1:
            fwd_iats = np.diff(flow['fwd_pkt_times'])
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

        # Backward IAT features
        if len(flow['bwd_pkt_times']) > 1:
            bwd_iats = np.diff(flow['bwd_pkt_times'])
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

        # Subflow features (simplified - assume whole flow is one subflow)
        feature_dict['Subflow Fwd Packets'] = flow['fwd_packet_count']
        feature_dict['Subflow Fwd Bytes'] = flow['total_fwd_bytes']
        feature_dict['Subflow Bwd Packets'] = flow['bwd_packet_count']
        feature_dict['Subflow Bwd Bytes'] = flow['total_bwd_bytes']

        # Init window bytes
        feature_dict['Init_Win_bytes_forward'] = flow['fwd_init_win']
        feature_dict['Init_Win_bytes_backward'] = flow['bwd_init_win']

        # Active data packets (simplified)
        feature_dict['act_data_pkt_fwd'] = 0
        feature_dict['min_seg_size_forward'] = 0

        # Active time statistics
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

        # Idle time statistics
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

        # Create feature vector in the order specified by feature_names
        feature_vector = []
        for feature_name in self.feature_names:
            if feature_name in feature_dict:
                feature_vector.append(feature_dict[feature_name])
            else:
                feature_vector.append(0)  # Default value for missing features

        return feature_vector
