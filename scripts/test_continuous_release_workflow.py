"""Release DAG contracts: parallel validation, joined publication, no new builds.

Uses the checked-in two-space job format and stdlib only; runner validation still
parses full Actions YAML. These tests exercise dependency/status truth tables.
"""
import ast
import itertools
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


def jobs(name):
    text = (ROOT / '.github/workflows' / name).read_text()
    body = text.split('\njobs:\n', 1)[1]
    return dict(re.findall(r'(?ms)^  ([\w-]+):\n(.*?)(?=^  [\w-]+:\n|\Z)', body))


def needs(block):
    value = re.search(r'^    needs: (.+)$', block, re.M)
    if not value:
        return []
    return [x.strip() for x in value[1].strip('[]').split(',')]


def condition(block, values):
    expression = re.search(r'^    if: (.+)$', block, re.M)[1].removeprefix('${{').removesuffix('}}').strip()
    for name in sorted(values, key=len, reverse=True):
        expression = expression.replace(name, repr(values[name]))
    expression = expression.replace('&&', ' and ').replace('||', ' or ')
    expression = re.sub(r'!(?!=)', ' not ', expression).strip()
    expression = re.sub(r'\btrue\b', 'True', expression)
    expression = re.sub(r'\bfalse\b', 'False', expression)
    tree = ast.parse(expression, mode='eval')
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq, ast.NotEq, ast.Constant, ast.UnaryOp, ast.Not)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise AssertionError('Unsupported publication condition')
    return eval(compile(tree, '<workflow condition>', 'eval'), {'__builtins__': {}})


class ReleaseWorkflow(unittest.TestCase):
    def setUp(self):
        self.continuous = jobs('continuous-release.yml')
        self.agent = jobs('agent-platforms.yml')

    def test_server_and_clients_start_after_same_immutable_prepare_only(self):
        self.assertEqual(needs(self.continuous['clients']), ['prepare'])
        self.assertEqual(needs(self.continuous['server']), ['prepare'])
        self.assertEqual(needs(self.continuous['clients-after-server']), ['prepare', 'server'])
        for name in ('server', 'clients', 'clients-after-server', 'publish'):
            self.assertIn('revision: ${{ needs.prepare.outputs.revision }}', self.continuous[name])
        self.assertIn('publish_release: false', self.continuous['clients'])
        self.assertNotIn('publish_release: ${{', self.continuous['clients'])
        self.assertEqual(self.continuous['clients'].split('    with:\n')[1], self.continuous['clients-after-server'].split('    with:\n')[1])

    def test_publication_joins_both_green_workflows_and_never_overrides_failure(self):
        publish = self.continuous['publish']
        self.assertEqual(set(needs(publish)), {'prepare', 'clients', 'clients-after-server', 'server'})
        for results in itertools.product(('success', 'failure', 'cancelled', 'skipped'), repeat=4):
            values = {f'needs.{name}.result': value for name, value in zip(('prepare', 'server', 'clients', 'clients-after-server'), results)}
            values.update({'needs.prepare.outputs.skip': 'false', 'needs.prepare.outputs.already_published': 'false', 'github.event_name': 'push', 'inputs.verify_only': False, 'cancelled()': False})
            expected = results[:2] == ('success', 'success') and results[2:] in (('success', 'skipped'), ('skipped', 'success'))
            self.assertEqual(condition(publish, values), expected, results)
            self.assertFalse(condition(publish, {**values, 'cancelled()': True}), results)
        self.assertNotIn('always()', publish)

    def test_verify_only_skip_and_already_published_never_publish(self):
        base = {'needs.prepare.result': 'success', 'needs.server.result': 'success', 'needs.clients.result': 'success', 'needs.clients-after-server.result': 'skipped', 'cancelled()': False, 'needs.prepare.outputs.skip': 'false', 'needs.prepare.outputs.already_published': 'false', 'github.event_name': 'workflow_dispatch', 'inputs.verify_only': False}
        self.assertTrue(condition(self.continuous['publish'], base))
        for update in ({'inputs.verify_only': True}, {'needs.prepare.outputs.skip': 'true'}, {'needs.prepare.outputs.already_published': 'true'}):
            self.assertFalse(condition(self.continuous['publish'], {**base, **update}))
        clients = self.continuous['clients']
        self.assertIn("platform: ${{ github.event_name == 'workflow_dispatch' && inputs.verify_only == true && inputs.platform || 'all' }}", clients)
        self.assertIn('verify_only: ${{ github.event_name ==', clients)

    def test_depot_default_and_explicit_opt_in_choose_exactly_one_build_lane(self):
        for depot, opted in itertools.product(('', 'https://trusted.example'), ('', 'false', 'true')):
            values = {'needs.prepare.outputs.skip': 'false', 'needs.prepare.outputs.already_published': 'false', 'vars.PORTHUB_TRUSTED_NATIVE_DEPOT': depot, 'vars.PORTHUB_PARALLEL_CLIENT_BUILDS': opted}
            parallel = condition(self.continuous['clients'], values)
            serial = condition(self.continuous['clients-after-server'], values)
            self.assertNotEqual(parallel, serial)
            self.assertEqual(parallel, not depot or opted == 'true')
            for skip_field in ('needs.prepare.outputs.skip', 'needs.prepare.outputs.already_published'):
                self.assertFalse(condition(self.continuous['clients'], {**values, skip_field: 'true'}))
                self.assertFalse(condition(self.continuous['clients-after-server'], {**values, skip_field: 'true'}))


    def test_standalone_agent_publish_remains_opt_in_after_complete_bundle(self):
        publish = self.agent['publish-release']
        self.assertEqual(needs(publish), ['release-bundle'])
        for verify, enabled, core in itertools.product((False, True), repeat=3):
            self.assertEqual(condition(publish, {'inputs.verify_only': verify, 'inputs.publish_release': enabled, 'inputs.core_only': core}), enabled and not verify and not core)
        self.assertIn('contents: write', publish)
        self.assertIn('revision: ${{ inputs.revision || github.sha }}', publish)
        self.assertIn('promote-existing', self.agent)

    def test_same_run_bundle_is_consumed_without_cross_run_fetch_or_rebuild(self):
        workflow = (ROOT / '.github/workflows/publish-client-bundle.yml').read_text()
        publish = jobs('publish-client-bundle.yml')['publish']
        self.assertIn('name: porthub-release-bundle', publish)
        self.assertIn('path: release-assets', publish)
        self.assertNotIn('run-id:', publish)
        self.assertNotIn('repository:', publish)
        self.assertNotIn('stage-verified-release.py', publish)
        self.assertNotIn('build-component-platform.py', publish)
        self.assertNotIn('build-agent-linux.sh', publish)
        self.assertIn('group: porthub-release-publication', publish)
        self.assertIn('cancel-in-progress: false', publish)
        self.assertIn('contents: write', publish)
        self.assertIn('test \"$GITHUB_REF\" = \"refs/heads/$DEFAULT_BRANCH\"', publish)
        self.assertIn('DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}', publish)
        self.assertIn('test_publish_release.py', publish)
        self.assertIn('--revision "$PORTHUB_SOURCE_REVISION"', publish)
        self.assertIn("['git', 'rev-parse', 'HEAD']", publish)
        self.assertIn('[a-f0-9]{40}', publish)
        self.assertNotIn('workflow_dispatch:', workflow)

    def test_default_branch_only_guard_executes_equally_for_standalone_and_joined_publish(self):
        publisher = jobs('publish-client-bundle.yml')['publish']
        command = re.search(r'run: (test "\$GITHUB_REF" = "refs/heads/\$DEFAULT_BRANCH")', publisher)[1]
        for ref, expected in (('refs/heads/main', True), ('refs/heads/feature', False), ('refs/tags/v1.2.3', False)):
            result = subprocess.run(['sh', '-c', command], env={'GITHUB_REF': ref, 'DEFAULT_BRANCH': 'main'}, capture_output=True)
            self.assertEqual(result.returncode == 0, expected)
        scope = self.agent['select-platforms']
        self.assertIn('test "$BUILD_PLATFORM" = all', scope)
        self.assertIn('test "$VERIFY_ONLY" != true', scope)
        self.assertIn(command, scope)


    def test_all_platform_gates_and_complete_artifact_assembly_are_preserved(self):
        bundle = self.agent['release-bundle']
        self.assertEqual(set(needs(bundle)), {'select-platforms', 'native', 'linux-32', 'media-helpers'})
        self.assertIn('Assemble and verify all ten platform artifacts', bundle)
        self.assertIn('name: porthub-release-bundle', bundle)
        for job in ('native', 'linux-32'):
            self.assertIn('fail-fast: false', self.agent[job])
        continuous = (ROOT / '.github/workflows/continuous-release.yml').read_text()
        self.assertIn("- '.github/workflows/publish-client-bundle.yml'", continuous)
        self.assertIn('python3 scripts/test_continuous_release_workflow.py', continuous)
        for caller in (self.continuous['publish'], self.agent['publish-release']):
            self.assertIn('uses: ./.github/workflows/publish-client-bundle.yml', caller)


if __name__ == '__main__':
    unittest.main()
