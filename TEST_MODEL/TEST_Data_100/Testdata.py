from sklearn.preprocessing import MinMaxScaler, QuantileTransformer
import pandas as pd

# Set seed value for reproducibility
seed = 42

# Load dataset
data = pd.read_csv("C:/Users/g23M8231/Desktop/TEST_MODEL/TEST_Data_100/DATA_TEST.csv")

# Drop the 'Name' column
data = data.drop('Name', axis=1)

# Separate target and features
target = data['Category']
X = data.drop('Category', axis=1)

# Define feature sets for scaling
features_min_max = ['SizeOfImage', 'Characteristics', 'SectionMinEntropy',
       'SizeOfInitializedData', 'SectionMaxEntropy', 'SectionMaxPointerData',
       'SizeOfCode', 'SectionMaxRawsize', 'ImageDirectoryEntryImport',
       'SectionMinVirtualsize', 'SectionMaxVirtualsize', 'SectionMaxPhysical',
       'SectionMinPhysical', 'AddressOfEntryPoint', 'TimeDateStamp',
       'DirectoryEntryImport', 'MajorLinkerVersion',
       'ImageDirectoryEntrySecurity', 'SectionMinRawsize', 'CheckSum',
       'Subsystem', 'SectionMaxChar', 'SizeOfHeapReserve',
       'DirectoryEntryExport', 'MinorLinkerVersion', 'SectionMainChar',
       'MajorSubsystemVersion', 'NumberOfSections', 'SectionsLength',
       'FileAlignment']

features_quantile = ['SizeOfImage', 'Characteristics', 'SizeOfInitializedData',
       'SectionMinEntropy', 'SectionMaxEntropy', 'SectionMaxPointerData',
       'SizeOfCode', 'SectionMaxRawsize', 'ImageDirectoryEntryImport',
       'SectionMinVirtualsize', 'SectionMaxVirtualsize', 'SectionMaxPhysical',
       'SectionMinPhysical', 'AddressOfEntryPoint', 'TimeDateStamp',
       'SectionMainChar', 'ImageDirectoryEntrySecurity', 'MinorLinkerVersion',
       'DirectoryEntryImport', 'CheckSum', 'Subsystem', 'SectionMaxChar',
       'NumberOfSections', 'DllCharacteristics', 'PointerToSymbolTable',
       'SectionMinPointerData', 'ImageDirectoryEntryExport',
       'DirectoryEntryExport', 'FileAlignment', 'SizeOfHeaders', 'ImageBase']

# Create scalers
min_max_scaler = MinMaxScaler()
quantile_transformer = QuantileTransformer(output_distribution='uniform', random_state=seed)

# Apply MinMaxScaler to selected features
X_min_max = X.copy()
X_min_max[features_min_max] = min_max_scaler.fit_transform(X_min_max[features_min_max])

# Apply QuantileTransformer to selected features
X_quantile = X.copy()
X_quantile[features_quantile] = quantile_transformer.fit_transform(X_quantile[features_quantile])

# Save transformed datasets
data_min_max = pd.concat([X_min_max, target], axis=1)
data_min_max.to_csv('minmaxdata.csv', index=False)

data_quantile = pd.concat([X_quantile, target], axis=1)
data_quantile.to_csv('quantiletransformeddata.csv', index=False)
