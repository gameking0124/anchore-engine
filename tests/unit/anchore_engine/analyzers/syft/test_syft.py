import pytest

from anchore_engine.analyzers.syft import filter_artifacts, is_ownership_allowed


class TestFilterArtifacts:
    @pytest.fixture()
    def supported_artifacts_by_type(self):
        return [
            {
                "name": "a-gem-pkg",
                "type": "gem",
            },
            {
                "name": "child-pkg",
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
                "name": "parent-pkg",
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

    def test_filter_by_type(
        self, supported_artifacts_by_type, unsupported_artifacts_by_type
    ):
        test_artifacts = supported_artifacts_by_type + unsupported_artifacts_by_type
        actual = list(filter_artifacts(test_artifacts))
        assert actual == supported_artifacts_by_type

    @pytest.mark.parametrize(
        "parent_type,child_type,expected_artifact_names",
        [
            # OS -> non OS package ownership : filtering applied
            ("rpm", "python", ["parent-pkg"]),
            ("deb", "python", ["parent-pkg"]),
            ("apk", "python", ["parent-pkg"]),
            # non-OS -> OS package ownership : filtering NOT applied
            ("python", "rpm", ["child-pkg", "parent-pkg"]),
            ("python", "deb", ["child-pkg", "parent-pkg"]),
            ("python", "apk", ["child-pkg", "parent-pkg"]),
            # OS -> OS package ownership : filtering applied
            ("rpm", "deb", ["parent-pkg"]),
            ("rpm", "rpm", ["parent-pkg"]),
            # non-OS -> non-OS package ownership : filtering applied
            ("python", "python", ["parent-pkg"]),
        ],
    )
    def test_filter_by_relations(
        self, parent_type, child_type, expected_artifact_names
    ):
        artifacts = [
            {
                "id": "child-id",
                "name": "child-pkg",
                "type": child_type,
                "relations": {
                    "parentsByFileOwnership": ["parent-id"],
                },
            },
            {
                "id": "parent-id",
                "name": "parent-pkg",
                "type": parent_type,
            },
        ]

        actual = list(filter_artifacts(artifacts))
        assert [a["name"] for a in actual] == expected_artifact_names

    @pytest.mark.parametrize(
        "parent_types,child_type,expected",
        [
            # OS -> non OS package ownership : allow
            (["rpm"], "python", True),
            (["deb"], "python", True),
            (["apk"], "python", True),
            # non-OS -> OS package ownership : deny
            (["python"], "rpm", False),
            (["python"], "deb", False),
            (["python"], "apk", False),
            # OS -> OS package ownership : allow
            (["rpm"], "deb", True),
            (["rpm"], "rpm", True),
            # non-OS -> non-OS package ownership : allow
            (["python"], "python", True),
            # mix of allowable
            (["apk", "rpm", "deb", "python"], "python", True),
            (["apk", "rpm", "deb"], "deb", True),
            # mix of denyable
            (["apk", "python", "deb"], "rpm", False),
            (["apk", "rpm", "python"], "deb", False),
        ],
    )
    def test_is_ownership_allowed(self, parent_types, child_type, expected):
        actual = is_ownership_allowed(child_type, parent_types)
        assert actual == expected
