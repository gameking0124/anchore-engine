import pytest

from anchore_engine.analyzers.syft import filter_artifacts


class TestFilterArtifacts:
    @pytest.fixture()
    def supported_artifacts_by_type(self):
        return [
            {
                "name": "a-gem-pkg",
                "type": "gem",
            },
            {
                "name": "a-python-pkg",
                "type": "python",
            },
            {
                "name": "a-npm-pkg",
                "type": "npm",
            },
            {
                "name": "a-java-pkg",
                "type": "java-archive",
            },
            {
                "name": "a-jenkins-pkg",
                "type": "jenkins-plugin",
            },
            {
                "name": "a-apk-pkg",
                "type": "apk",
            },
            {
                "name": "a-rpm-pkg",
                "type": "rpm",
            },
            {
                "name": "a-deb-pkg",
                "type": "deb",
            },
        ]

    @pytest.fixture()
    def unsupported_artifacts_by_type(self):
        return [
            {
                "name": "a-rando-pkg",
                "type": "rando",
            },
        ]

    @pytest.fixture()
    def artifacts_with_relations(self):
        return [
            {
                "name": "a-python-pkg",
                "type": "python",
                "relations": {
                    "parentsByFileOwnership": ["some-value"],
                },
            },
            {
                "name": "a-rpm-pkg",
                "type": "rpm",
            },
        ]

    def test_filter_by_type(
        self, supported_artifacts_by_type, unsupported_artifacts_by_type
    ):
        test_artifacts = supported_artifacts_by_type + unsupported_artifacts_by_type
        actual = list(filter(filter_artifacts, test_artifacts))
        assert actual == supported_artifacts_by_type

    def test_filter_by_relations(self, artifacts_with_relations):
        # we want to make certain that engine does NOT return packages that are owned by other packages
        # in the SBOM result (e.g. an RPM that has a python package included in the archive/manifest... only
        # the RPM should be reported).
        actual = list(filter(filter_artifacts, artifacts_with_relations))
        assert len(actual) == 1
        assert actual[0]["name"] == "a-rpm-pkg"
