import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report
import joblib
import os

def train_proper_model():
    print("Loading real-world dataset (CryptoAPI-Bench)...")
    dataset_path = 'data/real_crypto_snippets.csv'
    if not os.path.exists(dataset_path):
        print("Dataset not found. Please run parse_dataset.py first.")
        return
        
    df = pd.read_csv(dataset_path)
    df = df.dropna()
    
    # Filter classes with fewer than 3 instances to avoid CV split errors
    class_counts = df['label'].value_counts()
    valid_classes = class_counts[class_counts >= 3].index
    df = df[df['label'].isin(valid_classes)]
    
    X = df['code']
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Setting up Pipeline and Hyperparameter Grid...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4))),
        ('clf', SVC(probability=True, random_state=42))
    ])
    
    # Proper Hyperparameter Tuning
    param_grid = {
        'tfidf__max_features': [1000, 5000],
        'clf__C': [0.1, 1, 10],
        'clf__kernel': ['linear', 'rbf']
    }
    
    print("Running GridSearchCV for Best Parameters...")
    grid_search = GridSearchCV(pipeline, param_grid, cv=3, n_jobs=-1, verbose=1)
    grid_search.fit(X_train, y_train)
    
    print(f"Best Parameters Found: {grid_search.best_params_}")
    
    best_model = grid_search.best_estimator_
    
    print("Evaluating Model on Test Set...")
    predictions = best_model.predict(X_test)
    print("\nClassification Report:\n")
    print(classification_report(y_test, predictions))
    
    os.makedirs('models', exist_ok=True)
    model_path = 'models/crypto_classifier_proper.joblib'
    joblib.dump(best_model, model_path)
    print(f"Proper model saved successfully to {model_path}!")

if __name__ == "__main__":
    train_proper_model()
