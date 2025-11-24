# URL Threats Detection System

A machine learning-based system for detecting phishing and malicious URLs using advanced feature extraction and classification.

## Overview

This project implements a URL threat detection model that analyzes lexical and structural features of URLs to identify potentially dangerous links. The system uses a pre-trained classifier to predict whether a given URL is legitimate or malicious.

## Features

- **Advanced URL Feature Extraction**: Extracts 30+ lexical features including:
  - URL length and component ratios
  - Domain characteristics
  - Character entropy analysis
  - Special character patterns
  - Subdomain analysis
  
- **Machine Learning Classification**: Pre-trained model for binary classification (safe/phishing)

- **Web Interface**: Streamlit-based GUI for easy URL analysis

- **Real-time Predictions**: Instant threat assessment with confidence scores

## Project Structure

```
.
├── app.py                      # Streamlit web application
├── features_extract_new.py     # Feature extraction module
├── phishing_model.pkl          # Pre-trained ML model
├── scaler.pkl                  # Feature scaling model
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd "URL threats system"
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the Streamlit application:
```bash
streamlit run app.py
```

The application will open in your browser at `http://localhost:8501`

### How to Use

1. Enter a URL in the input field
2. Click the analyze button
3. View the prediction result (Safe/Phishing)
4. Review the confidence score and feature analysis

## Dependencies

- **streamlit** - Web framework for building the UI
- **pandas** - Data manipulation and analysis
- **scikit-learn** - Machine learning library
- **numpy** - Numerical computing
- **requests** - HTTP library for URL handling

## Model Details

- **Type**: Classification Model (Binary)
- **Classes**: Safe URL, Phishing URL
- **Features**: 30+ lexical features extracted from URL structure

## Contributing

Contributions are welcome! Please feel free to submit pull requests or issues.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Created for URL threat detection and cybersecurity research.

## Disclaimer

This tool is for educational and research purposes. Always use additional security measures and consult security professionals for critical applications.
