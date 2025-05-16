#!/usr/bin/env python3
"""
Utility untuk menguji model TFLite yang sudah dilatih secara terpisah dari sistem
"""
import argparse
import numpy as np
import tensorflow as tf
import time
import json
import os
import sys

def load_model(model_path):
    """Load and initialize TFLite model"""
    try:
        interpreter = tf.lite.Interpreter(model_path=model_path)
        interpreter.allocate_tensors()

        # Get input and output details
        input_details = interpreter.get_input_details()
        output_details = interpreter.get_output_details()

        print(f"Model loaded successfully from {model_path}")
        print(f"Input shape: {input_details[0]['shape']}")
        print(f"Output shape: {output_details[0]['shape']}")

        return interpreter, input_details, output_details
    except Exception as e:
        print(f"Error loading model: {e}")
        return None, None, None

def generate_test_sequence(sequence_length, num_features, scenario="normal"):
    """
    Generate test sequence with different patterns

    Args:
        sequence_length: Length of sequence
        num_features: Number of features per time step
        scenario: Type of traffic to simulate ("normal", "syn_flood", "port_scan")

    Returns:
        Numpy array with shape [sequence_length, num_features]
    """
    # Create base sequence with small random values (normal traffic)
    sequence = np.random.rand(sequence_length, num_features) * 0.2

    if scenario == "normal":
        # No modifications needed - just normal random values
        pass

    elif scenario == "syn_flood":
        # Simulate SYN flood by increasing SYN flag count and packet rate
        # Assuming 'SYN Flag Count' is feature index 7 (modify if different)
        syn_index = 7
        flow_rate_index = 13  # 'Flow Packets/s'

        # Increase SYN counts for all time steps
        sequence[:, syn_index] = np.linspace(0.5, 0.9, sequence_length)  # Increasing SYN trend

        # Increase packet rate
        sequence[:, flow_rate_index] = np.linspace(0.6, 0.95, sequence_length)  # Increasing rate

    elif scenario == "port_scan":
        # Simulate port scan with many small packets, varying destinations
        # Low packet sizes, high packet counts, low bytes/packet
        pkt_size_mean_index = 36  # 'Packet Length Mean'
        avg_pkt_size_index = 40  # 'Average Packet Size'
        flow_pkt_rate_index = 13  # 'Flow Packets/s'

        # Set low packet sizes
        sequence[:, pkt_size_mean_index] = np.random.rand(sequence_length) * 0.2 + 0.1
        sequence[:, avg_pkt_size_index] = np.random.rand(sequence_length) * 0.2 + 0.1

        # Set high packet rates but increasing over time
        sequence[:, flow_pkt_rate_index] = np.linspace(0.4, 0.8, sequence_length)

    elif scenario == "custom":
        # Let user create their own pattern by editing a JSON file
        if not os.path.exists("custom_pattern.json"):
            # Create template JSON if it doesn't exist
            template = {
                "description": "Custom attack pattern - edit feature values as needed",
                "features": {
                    "SYN Flag Count": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
                    "Flow Packets/s": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
                }
            }
            with open("custom_pattern.json", "w") as f:
                json.dump(template, f, indent=2)
            print(f"Created template at custom_pattern.json. Please edit and run again.")
            sys.exit(0)

        # Load custom pattern
        try:
            with open("custom_pattern.json", "r") as f:
                pattern = json.load(f)

            # Apply pattern to sequence
            for feature_name, values in pattern.get("features", {}).items():
                # Find feature index (this is simplified - in real usage, map to actual indices)
                feature_index = -1
                if feature_name == "SYN Flag Count":
                    feature_index = 7
                elif feature_name == "Flow Packets/s":
                    feature_index = 13
                # Add more mappings as needed

                if feature_index >= 0 and feature_index < num_features:
                    # Make sure we have enough values (pad or truncate)
                    if len(values) < sequence_length:
                        # Pad with last value
                        values = values + [values[-1]] * (sequence_length - len(values))
                    elif len(values) > sequence_length:
                        # Truncate
                        values = values[:sequence_length]

                    # Apply values
                    sequence[:, feature_index] = values
        except Exception as e:
            print(f"Error loading custom pattern: {e}")

    # Add a small amount of noise for realism
    sequence += np.random.rand(sequence_length, num_features) * 0.05

    # Clip values to [0, 1] for Min-Max scaled features
    sequence = np.clip(sequence, 0, 1)

    return sequence

def predict(interpreter, input_details, output_details, sequence):
    """Run prediction on a sequence"""
    start_time = time.time()

    # Ensure sequence has batch dimension
    if len(sequence.shape) == 2:
        sequence = np.expand_dims(sequence, axis=0)

    # Set input tensor
    interpreter.set_tensor(input_details[0]['index'], sequence.astype(np.float32))

    # Run inference
    interpreter.invoke()

    # Get output
    output = interpreter.get_tensor(output_details[0]['index'])
    prediction = float(output[0][0])

    # Calculate inference time
    inference_time = (time.time() - start_time) * 1000  # to milliseconds

    return prediction, inference_time

def main():
    parser = argparse.ArgumentParser(description='Test TFLite model for anomaly detection')
    parser.add_argument('--model', required=True, help='Path to TFLite model file')
    parser.add_argument('--scenario', default='normal', choices=['normal', 'syn_flood', 'port_scan', 'custom'],
                       help='Traffic scenario to simulate')
    parser.add_argument('--num_tests', type=int, default=10, help='Number of test predictions to run')

    args = parser.parse_args()

    # Load model
    interpreter, input_details, output_details = load_model(args.model)
    if interpreter is None:
        return

    # Get model dimensions
    _, sequence_length, num_features = input_details[0]['shape']
    print(f"Model expects sequences with shape: {sequence_length} time steps, {num_features} features")

    # Run tests
    print(f"\nRunning {args.num_tests} tests with scenario: {args.scenario}")
    print("-" * 60)
    print("| Test | Prediction | Is Anomaly | Inference Time (ms) |")
    print("-" * 60)

    total_time = 0
    anomaly_count = 0

    for i in range(args.num_tests):
        # Generate test sequence
        sequence = generate_test_sequence(sequence_length, num_features, args.scenario)

        # Run prediction
        prediction, inference_time = predict(interpreter, input_details, output_details, sequence)

        # Track stats
        total_time += inference_time
        is_anomaly = prediction > 0.5
        if is_anomaly:
            anomaly_count += 1

        # Print result
        print(f"| {i+1:4d} | {prediction:.6f} | {'Yes' if is_anomaly else 'No ':9s} | {inference_time:18.2f} |")

    print("-" * 60)

    # Print summary
    avg_time = total_time / args.num_tests
    print(f"\nSummary:")
    print(f"  Average inference time: {avg_time:.2f} ms")
    print(f"  Anomalies detected: {anomaly_count}/{args.num_tests} ({anomaly_count/args.num_tests*100:.1f}%)")
    print(f"  Scenario: {args.scenario}")

    # Print expected behavior
    if args.scenario == "normal":
        expected = "Normal traffic should mostly be classified as non-anomalous (low anomaly count)"
    elif args.scenario in ["syn_flood", "port_scan"]:
        expected = f"Attack traffic ({args.scenario}) should mostly be classified as anomalous (high anomaly count)"
    else:
        expected = "Depends on your custom pattern configuration"

    print(f"\nExpected behavior: {expected}")

    # Check if results match expectation
    if args.scenario == "normal" and anomaly_count / args.num_tests < 0.3:
        print("✅ Results match expectation for normal traffic")
    elif args.scenario in ["syn_flood", "port_scan"] and anomaly_count / args.num_tests > 0.7:
        print(f"✅ Results match expectation for {args.scenario}")
    elif args.scenario == "custom":
        print("⚠️ Unable to automatically validate custom pattern results")
    else:
        print("❌ Results do not match expectations - model may need retraining or the feature extraction process needs review")

if __name__ == "__main__":
    main()
