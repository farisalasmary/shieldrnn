#!/usr/bin/env python
# coding: utf-8

"""
    @author
          ______         _                  _
         |  ____|       (_)           /\   | |
         | |__ __ _ _ __ _ ___       /  \  | | __ _ ___ _ __ ___   __ _ _ __ _   _
         |  __/ _` | '__| / __|     / /\ \ | |/ _` / __| '_ ` _ \ / _` | '__| | | |
         | | | (_| | |  | \__ \    / ____ \| | (_| \__ \ | | | | | (_| | |  | |_| |
         |_|  \__,_|_|  |_|___/   /_/    \_\_|\__,_|___/_| |_| |_|\__,_|_|   \__, |
                                                                              __/ |
                                                                             |___/
            Email: farisalasmary@gmail.com
            Date:  Jul 29, 2021
"""

# This is the main Python script to train ShieldRNN

import time
import numpy as np
import pandas as pd
import pyshark
import pickle
import utils

import torch
import torch.nn as nn
from torch import optim
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report
from sklearn.neural_network import MLPClassifier
from sklearn import linear_model
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score


from sklearn.model_selection import GridSearchCV
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.linear_model import Lasso, LogisticRegression
from sklearn.feature_selection import SelectFromModel
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
import librosa
import random
import argparse
import sys

import seaborn as sns; sns.set()
np.set_printoptions(suppress=True)

import datetime
datetime.datetime.now()

"""
def predict(model, X_3d_tensor, threshold=0.5, device='cpu'):
    model.eval()
    with torch.no_grad():
        return (model(X_3d_tensor.to(device))[:, -1, :] > threshold).int()

"""

# majority voting
def predict(model, X_3d_tensor, threshold=0.5, device='cpu'):
    model.eval()
    with torch.no_grad():
        output = model(X_3d_tensor.to(device))
        output = (output >= 0.5).float() # VERY IMPORATANT STEP: we consider every label >= 0.5 as
                                         # 1 since we need it when we compute the correct average of
                                         # all predicted labels below
        y_pred = (output.mean(axis=1) >= threshold).float()
        return y_pred.int()


def train_model_outputs_per_packets(model, X_3d_train_tensor, y_3d_train_tensor, seq_lens, epochs=5, learning_rate=0.001, batch_size = 512, device='cpu'):
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    
    model.train()
    tmp_seq_lens = []
    for epoch in range(1, epochs + 1):
        
        if len(tmp_seq_lens) == 0:
            tmp_seq_lens = list(seq_lens)
            random.shuffle(tmp_seq_lens)
        
        new_seq_len = tmp_seq_lens.pop()
        
        reshaped_X_tensor, reshaped_y_tensor = split_examples(X_3d_train_tensor, y_3d_train_tensor, seq_len=new_seq_len)
        number_of_batches =  np.ceil(len(reshaped_X_tensor) / batch_size).astype(int) # number_of_batches = len(X_3d_train_tensor)

        for i, (x_batch, y_batch) in enumerate(batch_generator(reshaped_X_tensor, reshaped_y_tensor, batch_size, device)):
            # Training pass
            optimizer.zero_grad()

            output = model(x_batch)
            loss = criterion(output, y_batch)
            loss.backward()
            optimizer.step()
            
        del reshaped_X_tensor, reshaped_y_tensor
        torch.cuda.empty_cache()            
        if (epoch+1) % 1 == 0:
            print(f"Training loss: {loss.item():0.4f}, iteration: {i+1:4} / {number_of_batches:4}, epoch: {epoch:4} / {epochs:4}, seq_len: {new_seq_len:4}") #, end='\r')

    print(f"LAST Training loss: {loss.item()}")
    
    return model


class RNN(nn.Module):
    def __init__(self, input_size=27, hidden_layer_size=64, output_size=1):
#         super().__init__()
        super(RNN, self).__init__()
        self.rnn = nn.RNN(input_size, hidden_layer_size, batch_first=True, num_layers=1, bidirectional=True)
        self.dropout = nn.Dropout(0.5)
        self.linear = nn.Linear(hidden_layer_size*2, output_size)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, input_seq):
        rnn_out, h = self.rnn(input_seq)
        linear_out = self.linear(self.dropout(rnn_out))
        output = self.sigmoid(linear_out)
        
        return output

class LSTM(nn.Module):
    def __init__(self, input_size=27, hidden_layer_size=64, output_size=1):
#         super().__init__()
        super(LSTM, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_layer_size, batch_first=True, num_layers=1, bidirectional=True)
        self.dropout = nn.Dropout(0.5)
        self.linear = nn.Linear(hidden_layer_size*2, output_size)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, input_seq):
        lstm_out, h = self.lstm(input_seq)
        linear_out = self.linear(self.dropout(lstm_out))
        output = self.sigmoid(linear_out)
        
        return output


# THIS IS EXPERIMENTAL (TRYING to fix batch slicing in the loop)
def batch_generator(X_tensor, y_tensor, batch_size=64, device='cpu', shuffle=True):
    if shuffle:
        shuffled_indices = torch.randperm(X_tensor.size()[0])
        X_tensor = X_tensor[shuffled_indices, :, :]
        y_tensor = y_tensor[shuffled_indices, :, :]

    number_of_batches =  np.ceil(len(X_tensor) / batch_size).astype(int) # X_tensor.shape[0]
    for i in range(number_of_batches):
        X_3d_tensor = X_tensor[i*batch_size : (i*batch_size + batch_size)]
        y_3d_tensor = y_tensor[i*batch_size : (i*batch_size + batch_size)]

        yield X_3d_tensor.to(device), y_3d_tensor.to(device)


def split_examples(X_tensor, y_tensor, seq_len):
    X_tensor = X_tensor.detach().clone()
    y_tensor = y_tensor.detach().clone()
    
    # WARNING: some examples WILL BE DISCARDED
    new_num_examples = int(np.prod(X_tensor.shape) / (seq_len * X_tensor.shape[2]))
    
    old_num_examples = X_tensor.shape[0]
    old_seq_len = X_tensor.shape[1]
    input_dim = X_tensor.shape[2]
    output_dim = y_tensor.shape[2]
    
    # WARNING: some examples WILL BE DISCARDED
    X_tensor = X_tensor.reshape(old_num_examples*old_seq_len, -1, input_dim).squeeze(1)
    X_tensor = X_tensor[:new_num_examples*seq_len, :]
    
    y_tensor = y_tensor.reshape(old_num_examples*old_seq_len, -1, output_dim).squeeze(1)
    y_tensor = y_tensor[:new_num_examples*seq_len, :]

    reshaped_X_tensor = X_tensor.reshape(new_num_examples, seq_len, input_dim)
    reshaped_y_tensor = y_tensor.reshape(new_num_examples, seq_len, output_dim)
    
    return reshaped_X_tensor, reshaped_y_tensor


# ToDo: check and pad the last batch
#(batch, seq, feature)
def convert_rows_to_seq_tensor(X_tensor, y_tensor, seq_len):
    input_size = X_tensor.shape[1]
    output_size = y_tensor.shape[1]
    number_of_examples = np.floor(len(X_tensor) / seq_len).astype(int)
    
    X_3d_tensor = X_tensor[:(number_of_examples * seq_len)].reshape(
        number_of_examples, seq_len, input_size
    )
    y_3d_tensor = y_tensor[:(number_of_examples * seq_len)].reshape(
        number_of_examples, seq_len, output_size
    )

    return X_3d_tensor, y_3d_tensor


# ToDo: check and remove the padding from the last batch
def convert_seq_tensor_to_rows(X_3d_tensor, y_3d_tensor):
    seq_len = X_3d_tensor.shape[1]
    input_size = X_3d_tensor.shape[2]
    output_size = y_3d_tensor.shape[2]
    number_of_examples = len(X_3d_tensor)
    X = X_3d_tensor[:(number_of_examples * seq_len)].reshape(
            number_of_examples*seq_len, input_size
        )
    y = y_3d_tensor[:(number_of_examples * seq_len)].reshape(
            number_of_examples*seq_len, output_size
        )
    return X, y


def split_train_test_tensor(X_3d_tensor, y_3d_tensor, train_size, shuffle=True):
    # Define a size for your train set 
    train_size = int(train_size * len(X_3d_tensor))
    if shuffle:
        shuffled_indices = torch.randperm(X_3d_tensor.size()[0])
        X_3d_tensor = X_3d_tensor[shuffled_indices, :, :]
        y_3d_tensor = y_3d_tensor[shuffled_indices, :, :]
    
    # Split your dataset 
    X_3d_train_tensor = X_3d_tensor[:train_size]
    X_3d_test_tensor = X_3d_tensor[train_size:]

    y_3d_train_tensor = y_3d_tensor[:train_size]
    y_3d_test_tensor = y_3d_tensor[train_size:]

    return X_3d_train_tensor, X_3d_test_tensor, y_3d_train_tensor, y_3d_test_tensor


class MyStandardScaler:
    def __init__(self, features_list):
        self.scaler = StandardScaler(copy=True, with_mean=True, with_std=True)
        self.features_list = features_list

    def fit(self, X):
        self.scaler.fit(X[:, self.features_list])

    def transform(self, X):
        X = X.copy()
        X[:, self.features_list] = self.scaler.transform(X[:, self.features_list])
        
        return X
        
    def fit_transform(self, X):
        self.fit(X)
        return self.transform(X)



random_seq_lens = [5, 10, 20, 50, 100, 250, 500, 1000] # same as what was trained on 
# random_seq_lens = [26, 57, 77, 212, 329, 597, 643, 877] # randomly generated


def evaluate_models(X_3d_test_tensor, y_3d_test_tensor, models, seq_lens, device='cpu'):
    seq_lens.sort()
    
    model_metrics = {}
    for model_name, model in models.items():
        model_metrics[model_name] = {}
        for chosen_seq_len in seq_lens:
            model = model.to(device)
            x_test_tensor_tmp, y_test_tensor_tmp = split_examples(X_3d_test_tensor, y_3d_test_tensor, chosen_seq_len)
            
            y_pred = predict(model, x_test_tensor_tmp, threshold=0.5, device=device).cpu().numpy()
            y_true = (y_test_tensor_tmp.mean(axis=1) >= 0.5).int().cpu().numpy()
            
            accuracy_score_num = accuracy_score(y_true, y_pred)
            f1_score_num = f1_score(y_true, y_pred)
            precision_score_num = precision_score(y_true, y_pred)
            recall_score_num = recall_score(y_true, y_pred)
            classification_report_str = classification_report(y_true, y_pred)
            
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
            
            model_metrics[model_name][chosen_seq_len] = {
                                                            'f1_score': f1_score_num,
                                                            'accuracy_score': accuracy_score_num,
                                                            'classification_report': classification_report_str,
                                                            'precision_score': precision_score_num,
                                                            'recall_score': recall_score_num,
                                                            'tn': tn,
                                                            'fp': fp, 
                                                            'fn': fn,
                                                            'tp': tp
                                                        }
            
            
            print(f'seqlen: {chosen_seq_len}')
            print(f'x_test_tensor_tmp shape: {x_test_tensor_tmp.shape}')
            print(f'tn, fp, fn, tp: {tn} & {fp} & {fn} & {tp}')
            print(f'model name: {model_name}')
            print(f'accuracy: {accuracy_score_num}')
            print(f'f1 score: {f1_score_num}')
            print(f'precision: {precision_score_num}')
            print(f'recall: {recall_score_num}')
            print('#'*85)
            
    
    return model_metrics


def evaluate_light_classifier(X_test, y_test, models):
    y_true = y_test
    model_metrics = {}
    for model_name, model in models.items():
        y_pred = model.predict(X_test)
        accuracy_score_num = accuracy_score(y_true, y_pred)
        f1_score_num = f1_score(y_true, y_pred)
        precision_score_num = precision_score(y_true, y_pred)
        recall_score_num = recall_score(y_true, y_pred)
        classification_report_str = classification_report(y_true, y_pred)
        
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        
        model_metrics[model_name] = {
                                        'f1_score': f1_score_num,
                                        'accuracy_score': accuracy_score_num,
                                        'classification_report': classification_report_str,
                                        'precision_score': precision_score_num,
                                        'recall_score': recall_score_num,
                                        'tn': tn,
                                        'fp': fp, 
                                        'fn': fn,
                                        'tp': tp
                                    }
    
    return model_metrics




def metrics(tn, fp, fn, tp):
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    # changed var name from "f1_score" to "f1_score_value" since f1_score is a function in sklearn
    # and we do not want to overwrite it
    f1_score_value = 2*(precision * recall) / (precision + recall)
    return accuracy, f1_score_value, precision, recall


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Train ShieldRNN model')
    parser.add_argument('--dataset-csv-file', required=True,
                        help='The CSV file that contains the extracted features')

    parser.add_argument('--models-folder', default='my_models',
                        help='The folder where you want to save the trained models')

    parser.add_argument('--dataset-name', default='my_dataset',
                        help='The name of the dataset that is used. This helps to '
                             'distinguish trained models of different datasets')

    args = parser.parse_args()
    
    # Set the seed to 0 for reproducible results
    np.random.seed(0)
    torch.manual_seed(0)
    
    # The list of extracted features from PCAP files. The order of the features is important
    # since this script depends on this order in the data normalization part. The first 11 features
    # are assumed to follow the Gaussian distibution and hence they are normalized. Other features are
    # assumed to follow Bernolli distibution and they are not normalized since they have only two
    # values: [0, 1]
    features = [
                 'frame.len', 'ip.hdr_len', 'ip.len', 'ip.ttl', 'tcp.srcport', 'tcp.dstport', 'tcp.len','tcp.window_size',
                 'tcp.time_delta', 'flow_speed', 'tcp.ack', 'ip.flags.rb', 'ip.flags.df', 'ip.flags.mf', 'ip.frag_offset',
                 'tcp.flags.res', 'tcp.flags.ns', 'tcp.flags.cwr', 'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack',
                 'tcp.flags.push', 'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 
                 'is_TCP', 'is_UDP', 'is_ICMP', 'is_DNS', 'is_SSL', 'is_OTHER'
               ]
    
    
    models_folder = args.models_folder
    data_name = args.dataset_name
    
    
    print(f'Loading data: {args.dataset_csv_file}')
    data = pd.read_csv(args.dataset_csv_file)
    
    device = 'cpu' # force ALL upcoming data processing to be in CPU
    
    X = data[features].values
    y = (data['label'] == 'attack').astype(int).values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, shuffle=True, random_state=0)
    
    np.set_printoptions(suppress=True)
    
    # Normalize the first 11 features and leave the bit features unnormalized
    feature_list = list(range(0, 11))
    my_lasso_scaler = MyStandardScaler(feature_list)
    
    my_lasso_scaler.fit(X_train)
    
    X_train = my_lasso_scaler.transform(X_train)
    X_test = my_lasso_scaler.transform(X_test)
    
    
    # Grid search for the best regularization coefficient from a given set of coefficients
    reg_values = [0.0001, 0.001, 0.01, 0.1, 1.0, 10.0, 100.0] # list(np.logspace(-4, 2, 7))
    param_grid = {'C': reg_values }
    clf = GridSearchCV(LogisticRegression(solver='saga', penalty='l1', max_iter=1000),
                   param_grid, cv=5, verbose=1000, n_jobs=6)
    
    tic = time.time()
    clf.fit(X_train, y_train.reshape(-1))
    toc = time.time()
    
    print(f'GridSearch completed in {toc - tic}')
    
    best_classifier = clf.best_estimator_
    
    y_pred = best_classifier.predict(X_test)

    print('Classification Report of LASSO best classifier...')
    print(classification_report(y_test, y_pred))
    
    # Find the selected features by LASSO
    sel_ = SelectFromModel(best_classifier, prefit=True)

    lasso_selected_features = data[features].columns[(sel_.get_support())]
    lasso_removed_features = data[features].columns[~(sel_.get_support())]
    lasso_selected_features = list(lasso_selected_features)
    lasso_removed_features = list(lasso_removed_features)
    
    print('LASSO selected features:')
    print(lasso_selected_features)
    
    seq_lens = [5, 10, 20, 50, 100, 250, 500, 1000]
    
    # Find the largest seq_len to be used to split data
    seq_len = max(seq_lens)
    train_size = 0.9
    
    # Use the extracted LASSO features
    X = data[lasso_selected_features].values
    y = (data['label'] == 'attack').astype(int).values
    
    # Create PyTorch tensors
    X_tensor = torch.from_numpy(X.copy()).float().to(device)
    y_tensor = torch.from_numpy(y.copy()).reshape(-1, 1).float().to(device)
    
    # Convert the data matrix into 3D tensors using the largest sequence length in 
    # the provided list of sequence lengths
    X_3d_tensor, y_3d_tensor = convert_rows_to_seq_tensor(X_tensor, y_tensor, seq_len)
    
    # Split the data into training set and testing set
    X_3d_train_tensor, X_3d_test_tensor,\
    y_3d_train_tensor, y_3d_test_tensor = split_train_test_tensor(X_3d_tensor, y_3d_tensor, train_size) 
    
    # Convert the 3D tensors back into matrices after splitting
    X_train, y_train = convert_seq_tensor_to_rows(X_3d_train_tensor, y_3d_train_tensor)
    X_test, y_test = convert_seq_tensor_to_rows(X_3d_test_tensor, y_3d_test_tensor)
    
    # Standardize the data.
    # NOTE: Sometimes LASSO will discard some features from the first 11 features.
    # Hence, you should rearrange the features and change the number "11" inside 
    # the range() function below
    
    feature_list = list(range(0, 11))
    my_scaler = MyStandardScaler(feature_list)
    my_scaler.fit(X_train.cpu().numpy())
    
    X_train = my_scaler.transform(X_train.cpu().numpy())
    X_test = my_scaler.transform(X_test.cpu().numpy())
    
    # Convert the normalized data into PyTorch tensors
    X_train = torch.from_numpy(X_train.copy()).float().to(device)
    X_test = torch.from_numpy(X_test.copy()).float().to(device)
    
    # Convert the tensors into 3D tensors
    X_3d_train_tensor, y_3d_train_tensor = convert_rows_to_seq_tensor(X_train, y_train, seq_len)
    X_3d_test_tensor, y_3d_test_tensor = convert_rows_to_seq_tensor(X_test, y_test, seq_len)

    # Get the dimensions of the input and output
    input_size = X_3d_train_tensor.shape[2]
    output_size = y_3d_train_tensor.shape[2]
    
    # Models hyperparameters
    hidden_layer_size = 20
    epochs = 3000
    learning_rate = 0.001
    batch_size = 256
    
    # Check if there is a GPU to be used for training
    device = 'cuda' if torch.cuda.is_available() else 'cpu'

    print("input_size, output_size, device, X_3d_train_tensor.shape, y_3d_train_tensor.shape")
    print(input_size, output_size, device, X_3d_train_tensor.shape, y_3d_train_tensor.shape)
    
    # train LSTM model with ShieldRNN
    shieldrnn_lstm_model = LSTM(input_size, hidden_layer_size, output_size).to(device)
    print(shieldrnn_lstm_model)


    shieldrnn_lstm_model = train_model_outputs_per_packets(shieldrnn_lstm_model, X_3d_train_tensor, y_3d_train_tensor, seq_lens, epochs=epochs, learning_rate=learning_rate, batch_size=batch_size, device=device)
    print(shieldrnn_lstm_model)
    
    shieldrnn_rnn_model = RNN(input_size, hidden_layer_size, output_size).to(device)
    
    # train RNN model with ShieldRNN
    shieldrnn_rnn_model = train_model_outputs_per_packets(shieldrnn_rnn_model, X_3d_train_tensor, y_3d_train_tensor, seq_lens, epochs=epochs, learning_rate=learning_rate, batch_size=batch_size, device=device)
    print(shieldrnn_rnn_model)
    
    models = {}
    models['shieldrnn_lstm_model'] = shieldrnn_lstm_model
    models['shieldrnn_rnn_model'] = shieldrnn_rnn_model
    
    # Evaluate the trained models
    models_metrics = evaluate_models(X_3d_test_tensor, y_3d_test_tensor, models, seq_lens, device=device)
    
    # Show the overall performance of the LSTM model trained with ShieldRNN
    tn, fp, fn, tp = 0,0,0,0
    model_name = 'shieldrnn_lstm_model'
    for seq_len in models_metrics[model_name].keys():
        tn += models_metrics[model_name][seq_len]['tn']
        tp += models_metrics[model_name][seq_len]['tp']
        fp += models_metrics[model_name][seq_len]['fp']
        fn += models_metrics[model_name][seq_len]['fn']

    
    print("Calculated metrics of all sequence lengths:")
    accuracy, f1_score_value, precision, recall = metrics(tn, fp, fn, tp)
    print(f"Accuracy: {accuracy}, F1-score: {f1_score_value}, Precision: {precision}, Recall: {recall}")
    print(f'tn, fp, fn, tp: {tn} & {fp} & {fn} & {tp}')
    
    
    # Create the models folder if it does not exist
    models_folder = models_folder.rstrip('/')
    utils.makedirectory(models_folder)
    
    # Save all the models
    pickle.dump(my_lasso_scaler, open(f'{models_folder}/my_lasso_scaler_{data_name}.pkl', 'wb'))
    pickle.dump(my_scaler, open(f'{models_folder}/my_scaler_rnn_lstm_{data_name}.pkl', 'wb'))
    pickle.dump(lasso_selected_features, open(f'{models_folder}/LASSO_selected_features_{data_name}.pkl', 'wb'))
    pickle.dump(best_classifier, open(f'{models_folder}/LASSO_best_classifier_{data_name}.pkl', 'wb'))
    pickle.dump(clf, open(f'{models_folder}/LASSO_gridsearch_{data_name}.pkl', 'wb'))
    pickle.dump(models_metrics, open(f'{models_folder}/models_metrics_{data_name}.pkl', 'wb'))
      
    torch.save(shieldrnn_lstm_model, f'{models_folder}/shieldrnn_lstm_model_{data_name}.pth') #Save the state of the entire model
    torch.save(shieldrnn_rnn_model, f'{models_folder}/shieldrnn_rnn_model_{data_name}.pth') #Save the state of the entire model
    
    # Save the normalized data in matrix form
    train_test_normalized_data = {}
    train_test_normalized_data['X_train'] = X_train
    train_test_normalized_data['X_test'] = X_test
    train_test_normalized_data['y_train'] = y_train
    train_test_normalized_data['y_test'] = y_test
    torch.save(train_test_normalized_data, f'{models_folder}/train_test_normalized_data_{data_name}.pth') #Save the state of the entire model

    
