"""Tests for attribution tools model"""
from pathlib import Path, PurePath

import pytest

from attribution_tools.attribution_model import AttributionToolsModel, META_DATA_FILENAME
from attribution_tools.train_attribution_model import TrainingAttributionToolsModel

MODEL_PATH_LOCATION = "attribution_tools/data"
INTRUSION_SET_PATH = "tests/data/intrusion_sets_example.json"


class TestAttributionToolsModel:
    """The model that lables incidents by intrusions set labels"""

    @pytest.fixture(scope="function", autouse=True)
    def setup_preprocess(self):
        """Set up the class"""
        self.model = AttributionToolsModel()

    def test_predict_none(self):
        """Test that None string will be labeled by `-1`"""
        incident_val = self.model.predict(None)
        assert incident_val["label"] == -1, "Score for `None` should be -1."

    def test_predict_empty_str(self):
        """Test that empty string will be labeled as `-1`"""
        incident_val = self.model.predict("")
        assert incident_val["label"] == -1, "The score for `''` should be `-1`."

    def test_predict_with_none_model(self):
        """Check that `None` model will retrun `-2` label"""
        model = AttributionToolsModel(
            initial_path=PurePath(Path(__file__).parent.resolve(), "data"), model_name="model_test_None.pickle"
        )
        incident_val = model.predict("malware-fysbis attack-pattern-t1571")
        assert incident_val["label"] == -2, "The score, when model is `None`, should be `-2`."

    def test_predict_with_empty_model(self):
        """Check that empty model will return label `-3`"""
        model = AttributionToolsModel(
            initial_path=PurePath(Path(__file__).parent.resolve(), "data"), model_name="model_test_empty.pickle"
        )
        incident_val = model.predict("malware-fysbis attack-pattern-t1571")
        assert incident_val["label"] == -3, "The score, when model is `[]`, should be `-3`."

    def test_predict_wrong_model_location(self):
        """Check that wrong model location will result in `-2` label"""
        model = AttributionToolsModel(initial_path="")
        incident_val = model.predict("malware-fysbis attack-pattern-t1571")
        assert incident_val["label"] == -2, "The score for wrong model location should be `-2`."

    def test_db_version_format(self):
        """Check that when no db version is provided default version of db will be used"""
        incident_val = self.model.predict(None)
        assert len(incident_val["db_version"].split(",")) == 3, "The format of db should match."

    def test_db_default_version(self):
        """Check that with empty init params default model version is returned"""
        model = AttributionToolsModel()
        assert model.db_version == "(0, 0, 1)", "The format of default db should match."
