#!/usr/bin/env python3
"""
Utilitas untuk menghitung metrik performa deteksi anomali
"""
import argparse
import pandas as pd
import numpy as np
import json
import os
import sys
import re
from datetime import datetime
from sklearn.metrics import confusion_matrix, classification_report, precision_recall_fscore_support, roc_curve, auc

def parse_controller_log(log_path):
    """Parse controller log to extract detection results"""
    # Regex pattern untuk mencari log prediksi
    prediction_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*Flow ([\d\.:]+\-[\d\.:]+\-\d+): (ANOMALY|NORMAL) \(score: ([\d\.]+), time: ([\d\.]+)ms\)"

    # Arrays untuk menyimpan data
    timestamps = []
    flow_ids = []
    results = []
    scores = []
    inference_times = []

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

        # Create dataframe
        df = pd.DataFrame({
            'timestamp': timestamps,
            'flow_id': flow_ids,
            'result': results,
            'score': scores,
            'inference_time': inference_times
        })

        return df

    except Exception as e:
        print(f"Error parsing controller log: {e}")
        return pd.DataFrame()

def calculate_metrics(df, ground_truth_file=None):
    """
    Calculate performance metrics for anomaly detection

    Args:
        df: DataFrame with prediction results
        ground_truth_file: Path to JSON file with ground truth labels (optional)
                          Format: {"flow_id": 0/1, ...} where 1 is anomaly

    Returns:
        Dictionary with metrics
    """
    metrics = {}

    # Basic statistics
    if not df.empty:
        total_predictions = len(df)
        anomaly_count = sum(df['result'] == 'ANOMALY')
        normal_count = sum(df['result'] == 'NORMAL')

        metrics['total_predictions'] = total_predictions
        metrics['anomaly_count'] = anomaly_count
        metrics['normal_count'] = normal_count
        metrics['anomaly_ratio'] = anomaly_count / total_predictions if total_predictions > 0 else 0

        # Timing metrics
        metrics['mean_inference_time'] = df['inference_time'].mean()
        metrics['median_inference_time'] = df['inference_time'].median()
        metrics['max_inference_time'] = df['inference_time'].max()
        metrics['min_inference_time'] = df['inference_time'].min()
        metrics['std_inference_time'] = df['inference_time'].std()

        # Calculate percentage of inferences under different thresholds
        for threshold in [50, 100, 150, 200]:
            under_threshold = sum(df['inference_time'] < threshold)
            metrics[f'under_{threshold}ms_percentage'] = under_threshold / total_predictions * 100

    # If ground truth is provided, calculate classification metrics
    if ground_truth_file and os.path.exists(ground_truth_file):
        try:
            with open(ground_truth_file, 'r') as f:
                ground_truth = json.load(f)

            # Create arrays for predicted and actual labels
            y_true = []
            y_pred = []
            y_score = []

            for _, row in df.iterrows():
                flow_id = row['flow_id']
                if flow_id in ground_truth:
                    y_true.append(ground_truth[flow_id])
                    y_pred.append(1 if row['result'] == 'ANOMALY' else 0)
                    y_score.append(row['score'])

            # Only calculate if we have ground truth for some predictions
            if y_true:
                # Convert to numpy arrays
                y_true = np.array(y_true)
                y_pred = np.array(y_pred)
                y_score = np.array(y_score)

                # Calculate confusion matrix
                tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
                metrics['true_negative'] = int(tn)
                metrics['false_positive'] = int(fp)
                metrics['false_negative'] = int(fn)
                metrics['true_positive'] = int(tp)

                # Calculate derived metrics
                metrics['accuracy'] = (tp + tn) / (tp + tn + fp + fn)
                metrics['precision'] = tp / (tp + fp) if (tp + fp) > 0 else 0
                metrics['recall'] = tp / (tp + fn) if (tp + fn) > 0 else 0
                metrics['f1_score'] = 2 * metrics['precision'] * metrics['recall'] / (metrics['precision'] + metrics['recall']) if (metrics['precision'] + metrics['recall']) > 0 else 0
                metrics['false_positive_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0

                # Calculate ROC curve and AUC
                fpr, tpr, _ = roc_curve(y_true, y_score)
                metrics['roc_auc'] = auc(fpr, tpr)
                metrics['roc_curve'] = {'fpr': fpr.tolist(), 'tpr': tpr.tolist()}

                # Full classification report as string
                report = classification_report(y_true, y_pred)
                metrics['classification_report'] = report

        except Exception as e:
            print(f"Error calculating metrics with ground truth: {e}")

    return metrics

def generate_ground_truth_template(df, output_file):
    """
    Generate template for ground truth based on observed flows
    Creates a JSON file with all flows set to 0 (normal) by default

    Args:
        df: DataFrame with flow information
        output_file: Where to save the template
    """
    # Get unique flow IDs
    flow_ids = df['flow_id'].unique().tolist()

    # Create dictionary with all set to 0 (normal)
    ground_truth = {flow_id: 0 for flow_id in flow_ids}

    # Save to file
    with open(output_file, 'w') as f:
        json.dump(ground_truth, f, indent=2)

    print(f"Ground truth template created at {output_file}")
    print("Edit this file to mark anomalous flows with 1")

def main():
    parser = argparse.ArgumentParser(description='Calculate metrics for anomaly detection performance')
    parser.add_argument('--log', required=True, help='Path to controller log file')
    parser.add_argument('--output', default='metrics_results.json', help='Path to save metrics results')
    parser.add_argument('--ground-truth', help='Path to ground truth JSON file (optional)')
    parser.add_argument('--generate-template', action='store_true', 
                        help='Generate ground truth template based on observed flows')

    args = parser.parse_args()

    # Parse controller log
    print(f"Parsing controller log: {args.log}")
    df = parse_controller_log(args.log)

    if df.empty:
        print("No prediction data found in log. Exiting.")
        sys.exit(1)

    print(f"Found {len(df)} prediction events for {len(df['flow_id'].unique())} unique flows")

    # Generate ground truth template if requested
    if args.generate_template:
        template_file = 'ground_truth_template.json'
        generate_ground_truth_template(df, template_file)
        sys.exit(0)

    # Calculate metrics
    print("Calculating metrics...")
    metrics = calculate_metrics(df, args.ground_truth)

    # Save metrics to file
    with open(args.output, 'w') as f:
        json.dump(metrics, f, indent=2)

    # Print summary
    print("\nMetrics Summary:")
    print(f"Total predictions: {metrics.get('total_predictions', 0)}")
    print(f"Anomalies detected: {metrics.get('anomaly_count', 0)} ({metrics.get('anomaly_ratio', 0)*100:.1f}%)")
    print(f"Mean inference time: {metrics.get('mean_inference_time', 0):.2f} ms")
    print(f"Percentage under 100ms: {metrics.get('under_100ms_percentage', 0):.1f}%")

    if 'accuracy' in metrics:
        print("\nWith ground truth evaluation:")
        print(f"Accuracy: {metrics.get('accuracy', 0):.4f}")
        print(f"Precision: {metrics.get('precision', 0):.4f}")
        print(f"Recall: {metrics.get('recall', 0):.4f}")
        print(f"F1 Score: {metrics.get('f1_score', 0):.4f}")
        print(f"AUC-ROC: {metrics.get('roc_auc', 0):.4f}")
        print(f"\nConfusion Matrix:")
        print(f"TN: {metrics.get('true_negative', 0)}, FP: {metrics.get('false_positive', 0)}")
        print(f"FN: {metrics.get('false_negative', 0)}, TP: {metrics.get('true_positive', 0)}")

    print(f"\nDetailed metrics saved to {args.output}")

if __name__ == "__main__":
    main()
