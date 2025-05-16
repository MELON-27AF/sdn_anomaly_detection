from flask import Flask, request, jsonify
import numpy as np
import tensorflow as tf
import time
import logging

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("edge_node.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("edge-inference")

app = Flask(__name__)

# Path model TFLite (sesuaikan dengan lokasi model Anda)
MODEL_PATH = "models/cnn_lstm_cicids2017_colab.tflite"

# Load TFLite model
try:
    logger.info(f"Loading TFLite model from {MODEL_PATH}")
    interpreter = tf.lite.Interpreter(model_path=MODEL_PATH)
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()

    # Log model details
    logger.info(f"Model loaded successfully")
    logger.info(f"Input shape: {input_details[0]['shape']}")
    logger.info(f"Output shape: {output_details[0]['shape']}")

    # Extract expected dimensions from model
    _, sequence_length, num_features = input_details[0]['shape']
    logger.info(f"Sequence length: {sequence_length}, Features: {num_features}")

except Exception as e:
    logger.error(f"Error loading model: {e}")
    raise

@app.route('/predict', methods=['POST'])
def predict():
    start_time = time.time()
    try:
        # Get flow features from request
        flow_data = request.json

        if 'features' not in flow_data:
            return jsonify({'error': 'No features provided in request'}), 400

        # Extract features and ensure numpy array format
        features = np.array(flow_data['features'], dtype=np.float32)

        # Validate shape against model requirements
        if len(features.shape) == 2:
            # Single sequence [time_steps, features]
            if features.shape[0] != sequence_length:
                logger.warning(f"Input sequence length {features.shape[0]} doesn't match model's expected {sequence_length}")
                # Handle sequence length mismatch - trim or pad
                if features.shape[0] > sequence_length:
                    features = features[-sequence_length:, :]  # Take last sequence_length steps
                else:
                    # Pad with zeros at the beginning
                    padding = np.zeros((sequence_length - features.shape[0], features.shape[1]), dtype=np.float32)
                    features = np.vstack([padding, features])

            # Reshape to add batch dimension
            features = features.reshape(1, sequence_length, features.shape[1])

        elif len(features.shape) == 3:
            # Batch of sequences [batch, time_steps, features]
            if features.shape[1] != sequence_length:
                return jsonify({'error': f'Expected sequence length {sequence_length}, got {features.shape[1]}'}), 400
        else:
            return jsonify({'error': f'Invalid features shape: {features.shape}'}), 400

        # Ensure feature count matches model
        if features.shape[2] != num_features:
            logger.error(f"Feature count mismatch: got {features.shape[2]}, expected {num_features}")
            return jsonify({'error': f'Expected {num_features} features, got {features.shape[2]}'}), 400

        # Set input tensor
        interpreter.set_tensor(input_details[0]['index'], features)

        # Run inference
        interpreter.invoke()

        # Get output
        output = interpreter.get_tensor(output_details[0]['index'])
        prediction = float(output[0][0])

        # Calculate inference time
        inference_time = (time.time() - start_time) * 1000  # to milliseconds

        # Return prediction
        is_anomaly = prediction > 0.5
        logger.info(f"Prediction: {prediction:.4f} ({'ANOMALY' if is_anomaly else 'NORMAL'}) - Time: {inference_time:.2f}ms")

        return jsonify({
            'prediction': prediction,
            'is_anomaly': bool(is_anomaly),
            'inference_time_ms': inference_time
        })

    except Exception as e:
        logger.error(f"Error during inference: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'model_loaded': True})

if __name__ == '__main__':
    logger.info("Starting Edge Inference Service")
    app.run(host='0.0.0.0', port=5000)
