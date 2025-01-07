
import os
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, log_loss
from sklearn.model_selection import RandomizedSearchCV, GridSearchCV
from sklearn.ensemble import RandomForestClassifier 
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold
import xgboost as xgb


data_df = pd.read_csv('train.csv')
test_df = pd.read_csv('test.csv')

data_df.columns

test_df.columns



data_df.fillna(0,inplace=True)


test_df.fillna(0,inplace=True)

data_df

test_df
data_df['Label'].value_counts()



X_columns = [
    'ID', 'flow_duration', 'Header_Length', 'Protocol type', 'Duration',
       'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',
       'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
       'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count',
       'fin_count', 'urg_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS', 'Telnet',
       'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC',
       'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number',
       'Magnitue', 'Radius', 'Covariance', 'Variance', 'Weight'
]

# DF column used for the attack labels
y_column = 'Label'



# Creating a dictionary of attack types for 33 attack classes + 1 for benign traffic
dict_34_classes = {'BenignTraffic': 0 ,                                                                                                                         # Benign
                    'DDoS-RSTFINFlood' :1, 'DDoS-PSHACK_Flood':2,  'DDoS-SYN_Flood':3, 'DDoS-UDP_Flood':4, 'DDoS-TCP_Flood':5, 
                    'DDoS-ICMP_Flood':6, 'DDoS-SynonymousIP_Flood':7, 'DDoS-ACK_Fragmentation':8, 'DDoS-UDP_Fragmentation':9, 'DDoS-ICMP_Fragmentation':10, 
                    'DDoS-SlowLoris':11, 'DDoS-HTTP_Flood':12, 'DoS-UDP_Flood':13, 'DoS-SYN_Flood':14, 'DoS-TCP_Flood':15, 'DoS-HTTP_Flood':16,                 # DDoS and DoS
                    'Mirai-greeth_flood': 17, 'Mirai-greip_flood': 18, 'Mirai-udpplain': 19,                                                                    # Mirai 
                    'Recon-PingSweep': 20, 'Recon-OSScan': 21, 'Recon-PortScan': 22, 'VulnerabilityScan': 23, 'Recon-HostDiscovery': 24,                        # Reconnaissance
                    'DNS_Spoofing': 25, 'MITM-ArpSpoofing': 26,                                                                                                 # Spoofing
                    'BrowserHijacking': 27, 'Backdoor_Malware': 28, 'XSS': 29, 'Uploading_Attack': 30, 'SqlInjection': 31, 'CommandInjection': 32,              # Web
                    'DictionaryBruteForce': 33}  

# Binary classes
dict_2_classes = {  0: 0 ,                                                                                                                                      # Benign
                    1 :1, 2:1,  3:1, 4:1, 5:1, 6:1, 7:1, 8:1, 9:1, 10:1, 11:1, 12:1, 13:1, 14:1, 15:1, 16:1,                                                    # DDoS and DoS  
                    17: 1, 18: 1, 19: 1,                                                                                                                        # Mirai 
                    20: 1, 21: 1, 22: 1, 23: 1, 24: 1,                                                                                                          # Reconnaissance
                    25: 1, 26: 1,                                                                                                                               # Spoofing
                    27: 1, 28: 1, 29: 1, 30: 1, 31: 1, 32: 1,                                                                                                   # Web
                    33: 1}    



print(data_df.shape)
# Take a random sample of 5% of the rows
# data_df = data_df.sample(random_state=42)
data_df['Label'] = data_df['Label'].map(dict_34_classes)
data_df['Label'] = data_df['Label'].map(dict_2_classes)
num_unique_classes = len(data_df[y_column].unique())
print("unique classess: ", num_unique_classes)




scaler = StandardScaler()
data_df[X_columns] = scaler.fit_transform(data_df[X_columns])
test_df[X_columns] = scaler.fit_transform(test_df[X_columns])



print("Data 1 size: {}".format(data_df.shape))
print(data_df.info())
print("Test 1 size: {}".format(test_df.shape))
print(test_df.info())


data_df['Label'].value_counts()

data_df.to_csv('./preprocessed_data.csv')

data_df["Label"].value_counts()


# TRAIN MODEL

# # Create model Xgboost


X = data_df[X_columns]
y = data_df[y_column]

# Split the data into train and test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=123)
print("X_train: ", X_train.shape)
print("X_test: ", X_test.shape)
print("y_train: ", y_train.shape)
print("y_test: ", y_test.shape)


# Train the model
model = xgb.XGBClassifier()
model.fit(X_train, y_train)
print("Done training")
# Make predictions on the test set
y_pred = model.predict(X_test)
print("Done predicting")

# Calculate the accuracy
accuracy = accuracy_score(y_test, y_pred)
f1score  = f1_score(y_test, y_pred, average='weighted')
print("Original model Accuracy: %.2f%%" % (accuracy * 100.0))
print("Original model f1score: %.2f%%" % (f1score * 100.0))
print("Done")


# # Turnning Hyperparameter

def timer(start_time=None):
    if not start_time:
        start_time = datetime.now()
        return start_time
    elif start_time:
        thour, temp_sec = divmod((datetime.now() - start_time).total_seconds(), 3600)
        tmin, tsec = divmod(temp_sec, 60)
        print('\n Time taken: %i hours %i minutes and %s seconds.' % (thour, tmin, round(tsec, 2)))


# A parameter grid for XGBoost
params = {
        'min_child_weight': [1, 5, 10],
        'gamma': [0.5, 1, 1.5, 2, 5],
        'subsample': [0.6, 0.8, 1.0],
        'colsample_bytree': [0.6, 0.8, 1.0],
        'max_depth': [3, 4, 5]
        }


folds = 3
param_comb = 5

skf = StratifiedKFold(n_splits=folds, shuffle = True, random_state = 1001)

random_search = RandomizedSearchCV(model, param_distributions=params, n_iter=param_comb, scoring='f1', n_jobs=4, cv=skf.split(X_train,y_train), verbose=3, random_state=1001 )

# Here we go
start_time = timer(None) # timing starts from this point for "start_time" variable
random_search.fit(X_train, y_train)
timer(start_time) # timing ends here for "start_time" variable


print('\n All results:')
print(random_search.cv_results_)
print('\n Best estimator:')
print(random_search.best_estimator_)
print('\n Best normalized gini score for %d-fold search with %d parameter combinations:' % (folds, param_comb))
print(random_search.best_score_ * 2 - 1)
print('\n Best hyperparameters:')
print(random_search.best_params_)
results = pd.DataFrame(random_search.cv_results_)
results.to_csv('xgb-random-grid-search-results-01.csv', index=False)


# Tạo DMatrix từ dữ liệu 
dtrain = xgb.DMatrix(X_train, label=y_train) 
# Tạo hàm để in ra độ chính xác qua từng vòng lặp 
evals_result = {} 
#def custom_eval(preds, dtrain): 
 #   labels = dtrain.get_label() 
    #preds_labels = [1 if y > 0.5 else 0 for y in preds] 
  #  accuracy = accuracy_score(labels, preds) 
   # logloss = log_loss(labels, preds) 
   # return [('accuracy', accuracy), ('test_logloss', logloss)]
# Đặt tham số 
param = { 'objective': 'binary:logistic', 'subsample': 0.8, 'min_child_weight': 5, 'max_depth': 5, 'gamma': 1, 'colsample_bytree': 0.8 } 
# Huấn luyện mô hình 
fmodel = xgb.train(param, dtrain, num_boost_round=100)
      
# Huấn luyện mô hình và sử dụng hàm custom_eval để in ra kết quả
#fmodel = xgb.train(param, dtrain, num_boost_round=100, evals=[(dtrain, 'train')], evals_result=evals_result, verbose_eval=True, early_stopping_rounds = 30, custom_metric=custom_eval)


# Tạo DMatrix từ tập kiểm tra 
dtest = xgb.DMatrix(X_test, label=y_test) 
# Dự đoán kết quả 
fy_pred = fmodel.predict(dtest) 
fy_pred = [1 if y > 0.5 else 0 for y in fy_pred] 
# Ngưỡng 0.5 để phân loại # Tính Accuracy 
faccuracy = accuracy_score(y_test, fy_pred) 
print("Training Accuracy:", faccuracy * 100 , "%") 
# Tính F1-score 
ff1_score = f1_score(y_test, fy_pred) 
print("Training F1 Score:", ff1_score * 100 , "%") 


f1_test = xgb.DMatrix(test_df)

# Dự đoán kết quả 
f1_pred = fmodel.predict(f1_test)



f1_pred = [1 if y > 0.5 else 0 for y in fy_pred] 
# Ngưỡng 0.5 để phân loại # Tính Accuracy 
f1accuracy = accuracy_score(y_test, f1_pred) 
print("Validate Accuracy:", f1accuracy * 100 , "%") 
# Tính F1-score 
f1f1_score = f1_score(y_test, f1_pred) 
print("Validate F1 Score:", f1f1_score * 100 , "%") 



# Save the trained model
fmodel.save_model('model/bestf1.json')


# Load the saved model
loaded_model = xgb.XGBClassifier()
loaded_model.load_model('model/bestf1.json')



t_pred = loaded_model.predict(test_df)


t_pred = [1 if y > 0.5 else 0 for y in fy_pred] 
# Ngưỡng 0.5 để phân loại # Tính Accuracy 
taccuracy = accuracy_score(y_test, t_pred) 
print("Test Accuracy:", taccuracy * 100 , "%") 
# Tính F1-score 
tf1_score = f1_score(y_test, t_pred) 
print("Test F1 Score:", tf1_score * 100 , "%") 

