'''
    File: index.py
    Author: William Hua
    Purpose: Contains the main Flask application
'''
from . import helper
from flask import Flask, request, jsonify

app = Flask(__name__)

'''
    Function: index
    Purpose: Display a simple message
    Returns: A simple message
'''
@app.route('/')
def index():
    return 'Gone Phishing!'

'''
    Function: predict
    Purpose: Predict whether a URL is phishing
    Parameters:
        url: The URL to predict
    Returns: The prediction
'''
@app.route('/predict', methods=['GET'])
def predict():
    if not helper.le:
        return jsonify({'error': 'TLD encoder not loaded'}), 500
    
    if not helper.model:
        return jsonify({'error': 'Model not loaded'}), 500

    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        clean_url = helper.clean_url(url)
        features = helper.extract_features(clean_url)
        prediction = helper.model.predict(features)[0]
        response = {
            'prediction': int(prediction)
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
if __name__ == '__main__':
    app.run(debug=True)