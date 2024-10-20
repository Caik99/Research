from flask import Flask, render_template
import pandas as pd
import joblib
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.preprocessing import LabelEncoder
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for matplotlib
import matplotlib.pyplot as plt
import numpy as np
import io
import base64

app = Flask(__name__)

@app.route('/')
def index():

    # Load the pre-trained model
    model = joblib.load('C:/Users/g23M8231/Desktop/TEST_MODEL/Trained_Models/Saved_models/Random Forest_Quantile_No SMOTE.pkl')
    
    # Load the test data
    data = pd.read_csv('C:/Users/g23M8231/Desktop/TEST_MODEL/quantiletransformeddata.csv')

    # Get feature names from the model
    if hasattr(model, 'feature_names_in_'):
        model_features = model.feature_names_in_
    else:
        # If the model doesn't have feature_names_in_, we'll assume all columns except 'Category' were used
        model_features = [col for col in data.columns if col != 'Category']
    
    # Ensure test data has the same features as the model
    X_test = data[model_features]
    y_test = data['Category'].astype(int)
    
    # Make predictions
    y_pred = model.predict(X_test)
    
    # Define class names
    class_names = ['Benign', 'Ransomware', 'Trojan', 'Worms', 'Spyware', 'Virus']
    
    # Ensure class names match the unique labels in y_test or y_pred
    unique_labels = np.unique(np.concatenate((y_test, y_pred)))
    class_names = [class_names[i] for i in unique_labels if i < len(class_names)]
    
    # Compute confusion matrix
    cm = confusion_matrix(y_test, y_pred, labels=unique_labels)
    
    # Create confusion matrix plot
    fig, ax = plt.subplots(figsize=(10,8))
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    ax.set(
        xticks=np.arange(len(unique_labels)),
        yticks=np.arange(len(unique_labels)),
        xticklabels=class_names,
        yticklabels=class_names,
        ylabel='True label',
        xlabel='Predicted label',
        title='Confusion Matrix'
    )
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
    
    # Annotate cells with counts
    fmt = 'd'
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], fmt),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black")
    fig.tight_layout()
    
    # Convert plot to PNG image
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()
    
    # Compute classification report
    report = classification_report(y_test, y_pred, target_names=class_names, output_dict=True)
    
    return render_template('index.html', plot_url=plot_url, report=report, class_names=class_names)

if __name__ == '__main__':
    app.run(debug=True)
