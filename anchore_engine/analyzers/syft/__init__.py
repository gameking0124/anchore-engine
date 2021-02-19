import collections

from anchore_engine.analyzers.utils import defaultdict_to_dict, content_hints, dig
from anchore_engine.clients.syft_wrapper import run_syft
from .handlers import modules_by_artifact_type, modules_by_engine_type

def filter_relationships(relationships, **kwargs):

    def filter_fn(relationship):
        for key, expected in kwargs.items():
            if relationship[key] != expected:
                return False
        return True

    return filter(filter_fn, relationships)


def filter_artifacts(artifacts, relationships):

    def filter_fn(artifact):
        # syft may do more work than what is supported in engine, ensure we only include artifacts
        # of select package types.
        if artifact["type"] not in modules_by_artifact_type:
            return False

        # some packages are owned by other packages (e.g. a python package that was installed
        # from an RPM instead of with pip), filter out any packages that are not "root" packages.
        if list(filter_relationships(relationships, child=artifact['id'], type='ownership-by-files')):
            return False

        return True

    return filter(filter_fn, artifacts)


def catalog_image(imagedir):
    """
    Catalog the given image with syft, keeping only select artifacts in the returned results.
    """
    all_results = run_syft(imagedir)
    return convert_syft_to_engine(all_results)


def convert_syft_to_engine(all_results):
    """
    Do the conversion from syft format to engine format

    :param all_results:
    :return:
    """

    # transform output into analyzer-module/service "raw" analyzer json document
    nested_dict = lambda: collections.defaultdict(nested_dict)
    findings = nested_dict()

    # This is the only use case for consuming the top-level results from syft,
    # capturing the information needed for BusyBox. No artifacts should be
    # expected, and having outside of the artifacts loop ensure this will only
    # get called once.
    distro = all_results.get("distro")
    if distro and distro.get("name", "").lower() == "busybox":
        findings["package_list"]["pkgs.all"]["base"]["BusyBox"] = distro["version"]
    elif not distro or not distro.get("name"):
        findings["package_list"]["pkgs.all"]["base"]["Unknown"] = "0"

    # take a sub-set of the syft findings and invoke the handler function to
    # craft the artifact document and inject into the "raw" analyzer json
    # document
    for artifact in filter_artifacts(all_results["artifacts"], dig(all_results, "artifactRelationships", force_default=[])):
        handler = modules_by_artifact_type[artifact["type"]]
        handler.translate_and_save_entry(findings, artifact)

    return defaultdict_to_dict(findings)
