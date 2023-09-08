"""
Implementation of the Attribution Model
"""

import json
import logging
from pathlib import Path, PurePath

import dill as pickle
import pandas as pd

META_DATA_FILENAME = "meta_data.json"
MODEL_PATH_LOCATION = "data"
MODEL_NAME = "model.pickle"
DATABASE_VERSION = "(0, 0, 1)"
TOP_N = 3


class AttributionToolsModel:
    """The class used for initializing the model and making the predictions."""

    def __init__(
        self,
        model=None,
        database_version=DATABASE_VERSION,
        initial_path=None,
        model_name=MODEL_NAME,
        meta_file_name=META_DATA_FILENAME,
    ):
        self.log = logging.getLogger(__name__)
        self.db_version = database_version
        if model is None:
            if initial_path is None:
                initial_path = PurePath(Path(__file__).parent.resolve(), MODEL_PATH_LOCATION)
            self.log.info("Model is stored in %r", initial_path)
            self.meta_data_path_location = PurePath(initial_path, meta_file_name)
            self.model_path_location = PurePath(initial_path, model_name)
            self.model = None
        else:
            self.model = model

    def predict(self, incident_str):
        """Predict the intrusion set based on incident string"""
        if not isinstance(incident_str, str) or len(incident_str) == 0:
            return {"label": -1, "db_version": self.db_version}
        try:
            if self.model is None:
                self.model = self.load_files()
                if self.model is None:
                    return {"label": -2, "db_version": self.db_version}
            y_test_pred = self.model.predict_proba([incident_str])
            df_pred = pd.DataFrame(data={"labels": self.model.classes_, "probas": y_test_pred[0]})
            label_val = df_pred.sort_values(by=["probas"], ascending=False).head(TOP_N).to_dict("list")
            return {"label": label_val, "db_version": self.db_version}
        except Exception as exception:
            self.log.warning("The exception happened and the score can not be predicted for %r", incident_str)
            self.log.exception(exception)
        return {"label": -3, "db_version": self.db_version}

    def load_files(self):
        """Load the model and meta data"""
        try:
            if self.db_version == DATABASE_VERSION:
                with open(self.meta_data_path_location, "rb") as filename:
                    meta_data = json.load(filename)
                self.log.info("The model meta data downloaded from %s: ", self.meta_data_path_location)
                self.db_version = meta_data["db_version"]
                self.log.info(
                    "The model version is %s, the meta data creation time is %s: ",
                    meta_data["db_version"],
                    meta_data["time_metadata_created"],
                )
        except Exception as exception:
            self.log.warning("The exception happened and the json file can not be loaded")
            self.log.exception(exception)

        model = None
        try:
            with open(self.model_path_location, "rb") as filename:
                model = pickle.load(filename)
            self.log.info("The pickle file with model was loaded from %r location", self.model_path_location)
        except Exception as exception:
            self.log.warning("The exception happened and the pickle file can not be loaded")
            self.log.exception(exception)
        finally:
            return model
