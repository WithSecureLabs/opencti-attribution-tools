"""
Implementation of the Attribution Model Retraining module
"""

import logging

import pandas as pd
from packaging import version
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import BernoulliNB
from sklearn.pipeline import make_pipeline

from attribution_tools.generator import IncidentGenerator
from attribution_tools.parsers import get_instrusion_sets_stats
from attribution_tools.utils import increment_database_version

DATABASE_VERSION = "(0, 0, 1)"
N_PER_LABEL = 100


class TrainingAttributionToolsModel:
    """The attribution tools model is trained on generated incident data."""

    def __init__(self, intrusion_sets_data, database_version=DATABASE_VERSION, name=__name__):
        if not isinstance(intrusion_sets_data, list):
            intrusion_sets_data = []
        self.intrusion_sets_data = intrusion_sets_data
        if version.parse(database_version) > version.parse(DATABASE_VERSION):
            database_version = increment_database_version(database_version)
        self.database_version = database_version
        self.log = logging.getLogger(name)
        self.log.info("The number of intrusion set items %r", len(self.intrusion_sets_data))
        self.log.info("The data version is %r", self.database_version)

    def create_incident_data(self):
        """The incident data is generated using intrusion set data

        :return: pandas dataframe with incidents
        """
        intrusion_sets_stix = get_instrusion_sets_stats(self.intrusion_sets_data)
        generator = IncidentGenerator()
        dict_data = dict(items=[], label=[])

        for label_name, intrusion_set in intrusion_sets_stix.items():
            for _ in range(N_PER_LABEL):
                items = " ".join(generator.generate(intrusion_set))
                if not items:
                    items = " "
                dict_data["items"].append(items)
                dict_data["label"].append(label_name)

        pd_incidents = pd.DataFrame.from_dict(dict_data)
        return pd_incidents

    def retrain_model(self):
        """Performs all retraining work

        :return: in case of success returns new trained model and f1_score on test data and `None` otherwise
        """
        pd_incidents = self.create_incident_data()
        try:
            incidents = pd_incidents["items"].values
            incident_labels = pd_incidents["label"].values

            incidents_train, incidents_test, incident_labels_train, incident_labels_test = train_test_split(
                incidents, incident_labels, random_state=27, stratify=incident_labels, test_size=0.2
            )
            baseline_pipeline = make_pipeline(
                CountVectorizer(binary=True, tokenizer=lambda doc: doc.split(" ")),
                BernoulliNB(),
            )
            baseline_pipeline.fit(incidents_train, incident_labels_train)
            y_test_pred = baseline_pipeline.predict(incidents_test)
            f1_score_value = f1_score(incident_labels_test, y_test_pred, average="weighted")
            return baseline_pipeline, f1_score_value, self.database_version
        except Exception as exception_value:
            self.log.warning("The exception happened and the json file can not be loaded")
            self.log.exception(exception_value)

        return None
