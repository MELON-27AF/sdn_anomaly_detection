#!/usr/bin/env python3
"""
Utility untuk memvisualisasikan hasil deteksi anomali dari log sistem
"""
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import json
import re
from datetime import datetime
import os

def parse_controller_log(log_path):
    """
    Parse log controller untuk mengekstrak hasil deteksi anomali

    Args:
        log_path: Path ke file log controller

    Returns:
        DataFrame dengan hasil deteksi
    """
    # Regex patterns untuk mencari log prediksi
    prediction_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*Flow ([\d\.:]+\-[\d\.:]+\-\d+): (ANOMALY|NORMAL) \(score: ([\d\.]+), time: ([\d\.]+)ms\)"
    block_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*Blocked anomalous flow: ([\d\.:]+\-[\d\.:]+\-\d+) for (\d+) minutes"

    # Arrays untuk menyimpan data
    timestamps = []
    flow_ids = []
    results = []
    scores = []
    inference_times = []
    blocked = []

    # Parse log file
    try:
        with open(log_path, 'r') as f:
            log_content = f.read()

        # Extract prediction results
        prediction_matches = re.findall(prediction_pattern, log_content)
        for match in prediction_matches:
            timestamp_str, flow_id, result, score, inference_time = match
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')

            timestamps.append(timestamp)
            flow_ids.append(flow_id)
            results.append(result)
            scores.append(float(score))
            inference_times.append(float(inference_time))
            blocked.append(False)  # Will update when processing block matches

        # Extract block events and update the 'blocked' status
        block_matches = re.findall(block_pattern, log_content)
        block_flows = set()
        for match in block_matches:
            _, flow_id, _ = match
            block_flows.add(flow_id)

        # Update blocked status
        for i, flow_id in enumerate(flow_ids):
            if flow_id in block_flows:
                blocked[i] = True

        # Create dataframe
        df = pd.DataFrame({
            'timestamp': timestamps,
            'flow_id': flow_ids,
            'result': results,
            'score': scores,
            'inference_time': inference_times,
            'blocked': blocked
        })

        return df

    except Exception as e:
        print(f"Error parsing controller log: {e}")
        return pd.DataFrame()

def parse_edge_node_log(log_path):
    """
    Parse log edge node untuk mengekstrak informasi inference

    Args:
        log_path: Path ke file log edge node

    Returns:
        DataFrame dengan hasil inference
    """
    # Regex pattern untuk mencari log prediksi
    prediction_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*Prediction: ([\d\.]+) \((ANOMALY|NORMAL)\) - Time: ([\d\.]+)ms"

    # Arrays untuk menyimpan data
    timestamps = []
    scores = []
    results = []
    inference_times = []

    try:
        with open(log_path, 'r') as f:
            log_content = f.read()

        # Extract prediction results
        prediction_matches = re.findall(prediction_pattern, log_content)
        for match in prediction_matches:
            timestamp_str, score, result, inference_time = match
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')

            timestamps.append(timestamp)
            scores.append(float(score))
            results.append(result)
            inference_times.append(float(inference_time))

        # Create dataframe
        df = pd.DataFrame({
            'timestamp': timestamps,
            'score': scores,
            'result': results,
            'inference_time': inference_times
        })

        return df

    except Exception as e:
        print(f"Error parsing edge node log: {e}")
        return pd.DataFrame()

def plot_predictions_timeline(df, output_dir):
    """Plot timeline of predictions"""
    plt.figure(figsize=(12, 6))

    # Create color map
    colors = ['green' if r == 'NORMAL' else 'red' for r in df['result']]
    sizes = [30 if b else 10 for b in df['blocked']]

    # Plot scatter with colors based on result
    plt.scatter(df['timestamp'], df['score'], c=colors, s=sizes, alpha=0.7)

    # Add threshold line
    plt.axhline(y=0.5, color='black', linestyle='--', alpha=0.7, label='Threshold (0.5)')

    # Add labels and title
    plt.xlabel('Time')
    plt.ylabel('Anomaly Score')
    plt.title('Anomaly Detection Timeline')

    # Create custom legend
    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], marker='o', color='w', markerfacecolor='green', markersize=8, label='Normal'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=8, label='Anomaly'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=12, label='Blocked'),
        Line2D([0], [0], color='black', linestyle='--', label='Threshold')
    ]
    plt.legend(handles=legend_elements)

    # Format x-axis to show readable time
    plt.gcf().autofmt_xdate()

    # Save plot
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'predictions_timeline.png'))
    plt.close()

def plot_inference_time_histogram(df, output_dir):
    """Plot histogram of inference times"""
    plt.figure(figsize=(10, 6))

    # Plot histogram
    sns.histplot(df['inference_time'], kde=True, bins=20)

    # Add mean and median lines
    mean_time = df['inference_time'].mean()
    median_time = df['inference_time'].median()

    plt.axvline(mean_time, color='red', linestyle='--', 
                label=f'Mean: {mean_time:.2f} ms')
    plt.axvline(median_time, color='green', linestyle=':', 
                label=f'Median: {median_time:.2f} ms')

    # Add labels and title
    plt.xlabel('Inference Time (ms)')
    plt.ylabel('Frequency')
    plt.title('Distribution of Inference Times')
    plt.legend()

    # Save plot
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'inference_time_histogram.png'))
    plt.close()

def plot_score_distribution(df, output_dir):
    """Plot distribution of anomaly scores"""
    plt.figure(figsize=(10, 6))

    # Create separate dataframes for normal and anomaly
    normal_df = df[df['result'] == 'NORMAL']
    anomaly_df = df[df['result'] == 'ANOMALY']

    # Plot distributions
    sns.kdeplot(normal_df['score'], shade=True, label='Normal')
    sns.kdeplot(anomaly_df['score'], shade=True, label='Anomaly')

    # Add threshold line
    plt.axvline(0.5, color='black', linestyle='--', alpha=0.7, label='Threshold (0.5)')

    # Add labels and title
    plt.xlabel('Anomaly Score')
    plt.ylabel('Density')
    plt.title('Distribution of Anomaly Scores')
    plt.legend()

    # Save plot
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'score_distribution.png'))
    plt.close()

def generate_summary_report(controller_df, edge_df, output_dir):
    """Generate summary report with key metrics"""
    report = {}

    # Controller stats
    if not controller_df.empty:
        total_flows = len(controller_df['flow_id'].unique())
        total_packets = len(controller_df)
        anomaly_count = sum(controller_df['result'] == 'ANOMALY')
        normal_count = sum(controller_df['result'] == 'NORMAL')
        blocked_count = sum(controller_df['blocked'])

        report['controller'] = {
            'total_flows': total_flows,
            'total_detections': total_packets,
            'anomaly_count': anomaly_count,
            'normal_count': normal_count,
            'blocked_count': blocked_count,
            'anomaly_percentage': anomaly_count / total_packets * 100 if total_packets > 0 else 0,
        }

    # Edge node stats
    if not edge_df.empty:
        mean_inference_time = edge_df['inference_time'].mean()
        median_inference_time = edge_df['inference_time'].median()
        max_inference_time = edge_df['inference_time'].max()
        min_inference_time = edge_df['inference_time'].min()

        report['edge'] = {
            'total_inferences': len(edge_df),
            'mean_inference_time': mean_inference_time,
            'median_inference_time': median_inference_time,
            'max_inference_time': max_inference_time,
            'min_inference_time': min_inference_time,
            'below_100ms_percentage': sum(edge_df['inference_time'] < 100) / len(edge_df) * 100 if len(edge_df) > 0 else 0
        }

    # Save report to JSON
    with open(os.path.join(output_dir, 'summary_report.json'), 'w') as f:
        json.dump(report, f, indent=2)

    # Generate text report
    with open(os.path.join(output_dir, 'summary_report.txt'), 'w') as f:
        f.write("Summary Report for SDN Anomaly Detection\n")
        f.write("======================================\n\n")

        if 'controller' in report:
            f.write("Controller Statistics:\n")
            f.write("-----------------------\n")
            f.write(f"Total unique flows: {report['controller']['total_flows']}\n")
            f.write(f"Total detection events: {report['controller']['total_detections']}\n")
            f.write(f"Normal traffic events: {report['controller']['normal_count']}\n")
            f.write(f"Anomaly events: {report['controller']['anomaly_count']}\n")
            f.write(f"Blocked flows: {report['controller']['blocked_count']}\n")
            f.write(f"Anomaly percentage: {report['controller']['anomaly_percentage']:.2f}%\n\n")

        if 'edge' in report:
            f.write("Edge Node Performance:\n")
            f.write("----------------------\n")
            f.write(f"Total inferences: {report['edge']['total_inferences']}\n")
            f.write(f"Mean inference time: {report['edge']['mean_inference_time']:.2f} ms\n")
            f.write(f"Median inference time: {report['edge']['median_inference_time']:.2f} ms\n")
            f.write(f"Max inference time: {report['edge']['max_inference_time']:.2f} ms\n")
            f.write(f"Min inference time: {report['edge']['min_inference_time']:.2f} ms\n")
            f.write(f"Percentage of inferences below 100ms: {report['edge']['below_100ms_percentage']:.2f}%\n")

    return report

def main():
    parser = argparse.ArgumentParser(description='Visualize anomaly detection results from logs')
    parser.add_argument('--controller-log', help='Path to controller log file')
    parser.add_argument('--edge-log', help='Path to edge node log file')
    parser.add_argument('--output-dir', default='visualization_results', help='Directory to save visualizations')

    args = parser.parse_args()

    # Create output directory if not exists
    os.makedirs(args.output_dir, exist_ok=True)

    # Parse logs
    controller_df = pd.DataFrame()
    edge_df = pd.DataFrame()

    if args.controller_log:
        print(f"Parsing controller log: {args.controller_log}")
        controller_df = parse_controller_log(args.controller_log)
        print(f"Found {len(controller_df)} detection events")

    if args.edge_log:
        print(f"Parsing edge node log: {args.edge_log}")
        edge_df = parse_edge_node_log(args.edge_log)
        print(f"Found {len(edge_df)} inference events")

    # Check if we have data to visualize
    if controller_df.empty and edge_df.empty:
        print("No data found in logs. Please check log paths.")
        return

    # Create visualizations
    print("Generating visualizations...")

    if not controller_df.empty:
        print("Plotting predictions timeline...")
        plot_predictions_timeline(controller_df, args.output_dir)

        if 'blocked' in controller_df.columns:
            print("Generating score distribution plot...")
            plot_score_distribution(controller_df, args.output_dir)

    if not edge_df.empty:
        print("Plotting inference time histogram...")
        plot_inference_time_histogram(edge_df, args.output_dir)

    # Generate summary report
    print("Generating summary report...")
    report = generate_summary_report(controller_df, edge_df, args.output_dir)

    print(f"Visualizations and report saved to {args.output_dir}")

if __name__ == "__main__":
    main()
