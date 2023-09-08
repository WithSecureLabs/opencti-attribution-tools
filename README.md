# OpenCTI STIX2 Attribution Tools


## Description

The model is multi-label classifier and predicts Intrusion Set based on Incident. It was trained using Naive Bayes and both training and validation sets were generated.
  
### How to call parser to convert incident from `json` format to `string`
```python
from attribution_tools import parsers
parsers.incident_json_to_str(incident_json: dict) -> str
```
### How to retrain the model
```python
from attribution_tools.train_attribution_model import TrainingAttributionToolsModel
trained_values = TrainingAttributionToolsModel(intrusion_sets_data: list, database_version: string)
trained_values.retrain_model() -> (model, f1_score, incremented_database_version)
```
### Format of intrusion set
The value of `intrusion_sets_data` is list of dictionaries, where each dictionary is json representation of intrusion set. The `database_version` has a default value of `"(0, 0, 1)"` and if no value provided that value will be used. However, the database versions helps to track model version and check that the correct model version is used. 
### Retraining return value
Retraining module returns tuple value, where the first value is model and the second one is f1 score. F1 score value is a value between 0 and 1. Closer value is to 1, more accurate model is.
### How to call predict function
The value of `model` is `None` by default and in case no value provided the default model from repo will be used
```python
from attribution_tools.attribution_model import AttributionToolsModel
attribution_tools_model = AttributionToolsModel(model_value -> trained_values[0], database_version -> trained_values[2])
attribution_tools_model.predict(incident_str: str) -> json
```
### Format of prediction results
```python
{"label": {"labels": [str_intrusion-set, str_intrusion-set, str_intrusion-set], "probas": [double, double, double]}, "db_version": str}
```
In case of error, the `label` will take values:
*  `-1` in case of input parameter error;
*  `-2` if model is `None`;
*  `-3` if case of unexpected exception.
When everything passed successful, the string with 3 top intrusion set's and their probabilities will be returned.
### Example of returned value
```
{"label": {'labels': ['Aggah_intrusion-set--088d7359-97fb-591b-aeed-be46caf1027d', 'Kippis_intrusion-set--088d7359-2332-591b-aeed-be83caf1027d', 'UNC2891_intrusion-set--6520a731-fa8a-5232-ba9f-8e0bff785ad6'], 'probas': [0.9585474768119115, 0.04145252318808973, 0.03145252318808973]}, "db_version": "(0, 0, 1)"}
```

### CC-Driver
This package was developed as a part of [CC-Driver project](https://www.ccdriver-h2020.com/), funded by the European Union’s Horizon 2020 Research and Innovation Programme under Grant Agreement No. 883543