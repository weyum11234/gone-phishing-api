'''
    File: helper.py
    Author: William Hua
    Purpose: Contains helper functions for feature extraction
'''
import re
import math
import joblib
import pandas as pd
from tld import get_tld
from collections import Counter
from urllib.parse import urlparse
from spellchecker import SpellChecker
from sklearn.preprocessing import LabelEncoder

# Setup tools

with open('resources/phishing_keywords.txt', 'r') as file:
    phishing_keywords = file.read().splitlines()

try:
    le = joblib.load('resources/tld_encoder.pkl')
except Exception as e:
    print('Error loading TLD encoder:', e)
    le = None

try:
    with open('resources/model_reassembled.pkl', 'wb') as output_file:
        for chunk_id in range(88):
            with open(f'resources/model_part_{chunk_id}.pkl', 'rb') as input_file:
                output_file.write(input_file.read())
    model = joblib.load('resources/model_reassembled.pkl')
except Exception as e:
    print('Error loading model:', e)
    model = None

spell_check = SpellChecker()

# Helper functions

'''
    Function: clean_url
    Purpose: Clean a URL by removing the protocol
    Parameters:
        url: The URL to clean
    Returns: The cleaned URL
'''
def clean_url(url):
   return re.sub(r'^.*?://', '', url)

'''
    Function: split_url
    Purpose: Split a URL into words
    Parameters:
        url: The URL to split
    Returns: A list of words in the URL
'''
def split_url(url):
  parsed_url = urlparse(url)
  combined = parsed_url.netloc + parsed_url.path + parsed_url.query
  tokens = re.split(r'[\/\-_\.?=&]+', combined)
  return [token for token in tokens if (token and token.isalpha())]

'''
    Function: is_suspicious
    Purpose: Determine if a word is suspicious
    Parameters:
        word: The word to check
    Returns: True if the word is suspicious, False otherwise
'''
def is_suspicious(word):
  word_entropy = len(set(word)) / len(word)
  return (word not in spell_check and len(word) > 4 and word_entropy > 0.4)

'''
    Function: extract_features
    Purpose: Extract features from a given URL
    Parameters:
        url: The URL to extract features from
    Returns: A dictionary containing the extracted features
'''
def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['url_num_slash'] = url.count('/')
    features['url_num_equal'] = url.count('=')
    features['url_num_hyphen'] = url.count('-')
    features['url_num_dots'] = url.count('.')

    tld = get_tld('http://' + url, fail_silently=True)
    if tld and isinstance(tld, str):
        features['url_tlds'] = le.transform([tld])[0]
    else:
        features['url_tlds'] = 0

    features['url_pct_numeric'] = sum(c.isdigit() for c in url) / len(url)
    features['url_num_phishing_words'] = sum(1 for word in phishing_keywords if word in url.lower())

    splitted_url = split_url(url)
    features['url_num_mispelled_words'] = sum(1 for word in splitted_url if is_suspicious(word))

    char_freq = Counter(url)
    entropy = 0.0
    total_chars = len(url)
    for char, freq in char_freq.items():
        prob = freq / total_chars
        entropy += -prob * math.log2(prob)
    features['url_char_entropy'] = entropy

    return pd.DataFrame([features])
